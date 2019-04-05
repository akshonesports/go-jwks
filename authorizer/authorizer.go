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

// Option is an option for an Authorizer.
type Option func(*Authorizer)

// WithAudience returns an authorizer option for audience.
func WithAudience(aud string) Option {
	return func(authorizer *Authorizer) {
		authorizer.Audience = aud
	}
}

// WithIssuer returns an authorizer option for issuer.
func WithIssuer(iss string) Option {
	return func(authorizer *Authorizer) {
		authorizer.Issuer = iss
	}
}

// WithAlgorithms returns an authorizer option for algorithms.
func WithAlgorithms(algs ...jwks.Algorithm) Option {
	return func(authorizer *Authorizer) {
		authorizer.Algorithms = algs
	}
}

// WithHeader returns an authorizer option for header.
func WithHeader(header string) Option {
	return func(authorizer *Authorizer) {
		authorizer.Header = header
	}
}

// WithTokenFunc returns an authorizer option for header.
func WithTokenFunc(tokenFunc TokenFunc) Option {
	return func(authorizer *Authorizer) {
		authorizer.TokenFunc = tokenFunc
	}
}

type TokenFunc func(r *http.Request) string

// Authorizer is an http.Handler that authenticates HTTP requests.
type Authorizer struct {
	keys jwks.JSONWebKeySet
	next http.Handler

	mu    sync.RWMutex
	cache map[string]*result

	// Audience is the expected token audience.
	//
	// Authorization will fail if the token audience does not match this value.
	//
	// Leave this value empty to allow any audience value.
	Audience string

	// Issuer is the expected token issuer.
	//
	// Authorization will fail if the token issuer does not match this value.
	//
	// Leave this value empty to allow any issuer value.
	Issuer string

	// Algorithms is a whitelist of algorithms used to verify a token.
	//
	// Authorization will fail if the token algorithm is not one the given
	// values.
	//
	// Leave this value empty to allow any algorithm.
	Algorithms []jwks.Algorithm

	// Header is the authorization header.
	//
	// Leave this value empty to use "Authorization".
	Header string

	// TokenFunc is a function that returns the token from the http.Request
	TokenFunc TokenFunc
}

// New creates a new Authorizer with an http.Handler.
func New(ks jwks.JSONWebKeySet, handler http.Handler, options ...Option) *Authorizer {
	authorizer := &Authorizer{
		keys: ks,
		next: handler,
		cache: make(map[string]*result),
	}

	for _, apply := range options {
		apply(authorizer)
	}

	return authorizer
}

// Func creates a new Authorizer with an http.HandlerFunc.
func Func(ks jwks.JSONWebKeySet, handler http.HandlerFunc, options ...Option) *Authorizer {
	return New(ks, handler, options...)
}

// Middleware returns an http middleware function.
func Middleware(ks jwks.JSONWebKeySet, options ...Option) func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return New(ks, handler, options...)
	}
}

func (a *Authorizer) keyfunc(token *jwt.Token) (interface{}, error) {
	keyID, _ := token.Header["kid"].(string)
	key, err := a.keys.Key(keyID)
	if err != nil {
		return nil, err
	}

	if len(a.Algorithms) == 0 {
		return key.Key, nil
	}

	alg, _ := token.Header["alg"].(string)
	for _, algo := range a.Algorithms {
		if string(algo) == alg {
			return key.Key, nil
		}
	}

	return nil, ErrBadAlgorithm
}

func (a *Authorizer) token(r *http.Request) (string, error) {
	var token string
	if a.TokenFunc != nil {
		token = a.TokenFunc(r)
	} else {
		header := a.Header
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

func (a *Authorizer) Validate(token string) (map[string]interface{}, error) {
	claims := make(jwt.MapClaims)
	if _, err := jwt.ParseWithClaims(token, claims, a.keyfunc); err != nil {
		return nil, err
	}

	if a.Issuer != "" && !claims.VerifyIssuer(a.Issuer, true) {
		return claims, ErrInvalidIssuer
	}

	if a.Audience != "" && !verifyAud(claims["aud"], a.Audience) {
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

// ServerHTTP authenticates the HTTP request.
func (a *Authorizer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	defer func() {
		a.next.ServeHTTP(w, r.WithContext(ctx))
	}()

	token, err := a.token(r)
	if err != nil {
		ctx = setError(ctx, err)
		return
	}

	if res := a.check(token); res != nil {
		ctx = setResult(ctx, res)
		return
	}

	ctx = setToken(ctx, token)

	claims, err := a.Validate(token)
	if err != nil {
		ctx = setError(ctx, err)
		return
	}

	ctx = setClaims(ctx, claims)

	a.prime(ctx)
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
