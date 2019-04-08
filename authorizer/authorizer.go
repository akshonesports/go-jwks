package authorizer

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/akshonesports/go-jwks"
	"github.com/dgrijalva/jwt-go"
)

const defaultHeader = "Authorization"

var (
	ErrInvalidAudience = errors.New("invalid audience")
	ErrInvalidIssuer   = errors.New("invalid issuer")
	ErrBadAlgorithm    = errors.New("algorithm not allowed")
	ErrInvalidHeader   = errors.New("invalid authorization header")
	ErrMissingHeader   = errors.New("missing authorization header")
	ErrMissingToken    = errors.New("missing authorization token")
)

type options struct {
	aud  string
	iss  string
	algs []jwks.Algorithm

	handlerOptions []HandlerOption
}

func readOptions(opts []Option) *options {
	o := new(options)
	for _, apply := range opts {
		apply(o)
	}
	return o
}

// Option is an option for an Authorizer.
type Option func(*options)

// WithAudience returns an authorizer option for audience.
//
// Audience is the expected token audience.
//
// Authorization will fail if the token audience does not match this value.
//
// Leave this value empty to allow any audience value.
func WithAudience(aud string) Option {
	return func(opts *options) {
		opts.aud = aud
	}
}

// WithIssuer returns an authorizer option for issuer.
//
// Issuer is the expected token issuer.
//
// Authorization will fail if the token issuer does not match this value.
//
// Leave this value empty to allow any issuer value.
func WithIssuer(iss string) Option {
	return func(opts *options) {
		opts.iss = iss
	}
}

// WithAlgorithms returns an authorizer option for algorithms.
//
// Algorithms is a whitelist of algorithms used to verify a token.
//
// Authorization will fail if the token algorithm is not one the given
// values.
//
// Leave this value empty to allow any algorithm.
func WithAlgorithms(algs ...jwks.Algorithm) Option {
	return func(authorizer *options) {
		authorizer.algs = algs
	}
}

// WithHandlerOptions returns an authorizer option for handler options.
func WithHandlerOptions(hopts ...HandlerOption) Option {
	return func(opts *options) {
		opts.handlerOptions = hopts
	}
}

type HandlerOption func(*handler)

// WithHeader returns an authorizer option for header.
//
// Header is the authorization header.
//
// Leave this value empty to use "Authorization".
func WithHeader(header string) HandlerOption {
	return func(h *handler) {
		h.header = header
	}
}

// WithTokenFunc returns an authorizer option for header.
//
// TokenFunc is a function that returns the token from the http.Request
func WithTokenFunc(tokenFunc TokenFunc) HandlerOption {
	return func(h *handler) {
		h.tokenFunc = tokenFunc
	}
}

// TokenFunc extracts a token from an *http.Request
type TokenFunc func(r *http.Request) string

type handler struct {
	*Authorizer

	next http.Handler

	header    string
	tokenFunc TokenFunc
}

// ServerHTTP authenticates the HTTP request.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer func() {
		h.next.ServeHTTP(w, r.WithContext(ctx))
	}()

	token, err := h.token(r)
	if err != nil {
		ctx = setError(ctx, err)
		return
	}

	if res := h.check(token); res != nil {
		ctx = setResult(ctx, res)
		return
	}

	ctx = setToken(ctx, token)

	claims, err := h.Validate(token)
	if err != nil {
		ctx = setError(ctx, err)
		return
	}

	ctx = setClaims(ctx, claims)

	h.prime(ctx)
}

func (h *handler) token(r *http.Request) (string, error) {
	var token string
	if h.tokenFunc != nil {
		token = h.tokenFunc(r)
	} else {
		header := h.header
		if header == "" {
			header = defaultHeader
		}

		authorizationHeader := r.Header.Get(header)
		if authorizationHeader == "" {
			return "", ErrMissingHeader
		}

		if !strings.HasPrefix(authorizationHeader, "Bearer ") {
			return "", ErrInvalidHeader
		}

		token = authorizationHeader[7:]
	}

	if token == "" {
		return "", ErrMissingToken
	}

	return token, nil
}

// Authorizer is an http.Handler that authenticates HTTP requests.
type Authorizer struct {
	keys jwks.JSONWebKeySet

	mu    sync.RWMutex
	cache map[string]*result

	aud  string
	iss  string
	algs []jwks.Algorithm
}

func createAuthorizer(ks jwks.JSONWebKeySet, opts *options) *Authorizer {
	return &Authorizer{
		keys:  ks,
		cache: make(map[string]*result),
		aud:   opts.aud,
		iss:   opts.iss,
		algs:  opts.algs,
	}
}

// New creates a new Authorizer.
func New(ks jwks.JSONWebKeySet, opts ...Option) *Authorizer {
	return createAuthorizer(ks, readOptions(opts))
}

// Handler creates a new Authorizer handler.
func Handler(ks jwks.JSONWebKeySet, next http.Handler, options ...Option) http.Handler {
	o := readOptions(options)
	return createAuthorizer(ks, o).Handler(next, o.handlerOptions...)
}

// HandlerFunc creates a new Authorizer with an http.HandlerFunc.
func HandlerFunc(ks jwks.JSONWebKeySet, next http.HandlerFunc, options ...Option) http.HandlerFunc {
	o := readOptions(options)
	return createAuthorizer(ks, o).Handler(next, o.handlerOptions...).ServeHTTP
}

// Middleware returns an http middleware function.
func Middleware(ks jwks.JSONWebKeySet, options ...Option) func(http.Handler) http.Handler {
	o := readOptions(options)
	return createAuthorizer(ks, o).Middleware(o.handlerOptions...)
}

// Handler creates a new Authorizer handler.
func (a *Authorizer) Handler(next http.Handler, opts ...HandlerOption) http.Handler {
	h := &handler{
		Authorizer: a,
		next:       next,
	}

	for _, apply := range opts {
		apply(h)
	}

	return h
}

// Middleware returns an http middleware function.
func (a *Authorizer) Middleware(opts ...HandlerOption) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return a.Handler(next, opts...)
	}
}

func (a *Authorizer) keyfunc(token *jwt.Token) (interface{}, error) {
	keyID, _ := token.Header["kid"].(string)
	key, err := a.keys.Key(keyID)
	if err != nil {
		return nil, err
	}

	if len(a.algs) == 0 {
		return key.Key, nil
	}

	alg, _ := token.Header["alg"].(string)
	for _, algo := range a.algs {
		if string(algo) == alg {
			return key.Key, nil
		}
	}

	return nil, ErrBadAlgorithm
}

// Validate validates a token.
func (a *Authorizer) Validate(token string) (map[string]interface{}, error) {
	claims := make(jwt.MapClaims)
	if _, err := jwt.ParseWithClaims(token, claims, a.keyfunc); err != nil {
		return nil, err
	}

	if a.iss != "" && !claims.VerifyIssuer(a.iss, true) {
		return claims, ErrInvalidIssuer
	}

	if a.aud != "" && !verifyAud(claims["aud"], a.aud) {
		return claims, ErrInvalidAudience
	}

	if err := claims.Valid(); err != nil {
		return claims, err
	}

	return claims, nil
}

func verifyAud(aud interface{}, expected string) bool {
	switch aud := aud.(type) {
	case []string:
		for _, aud := range aud {
			if subtle.ConstantTimeCompare([]byte(expected), []byte(aud)) == 1 {
				return false
			}
		}
	case string:
		if subtle.ConstantTimeCompare([]byte(expected), []byte(aud)) == 0 {
			return false
		}
	}

	return true
}

func (a *Authorizer) check(token string) *result {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.cache[token]
}

func (a *Authorizer) prime(ctx context.Context) {
	_, res := getResult(ctx)
	exp, ok := res.claims["exp"].(json.Number)
	if !ok {
		return
	}

	t, err := exp.Int64()
	if err != nil {
		return
	}

	expiresIn := time.Unix(t, 0).Sub(time.Now())
	if expiresIn <= 0 {
		return
	}

	time.AfterFunc(expiresIn, func() {
		a.mu.Lock()
		defer a.mu.Unlock()

		delete(a.cache, res.token)
	})

	a.mu.RLock()
	defer a.mu.RUnlock()

	a.cache[res.token] = res
}

// ErrorHandler returns a http.Handler that handles authorizer errors.
func ErrorHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := Error(r.Context())
		if _, ok := err.(*jwt.ValidationError); ok {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		switch err {
		case ErrMissingHeader, ErrInvalidIssuer, ErrInvalidAudience:
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		case ErrInvalidHeader:
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		case nil:
			next.ServeHTTP(w, r)
		}
	})
}

// ErrorHandlerFunc is the same as ErrorHandler for http.HandlerFunc.
func ErrorHandlerFunc(next http.HandlerFunc) http.Handler {
	return ErrorHandler(next)
}
