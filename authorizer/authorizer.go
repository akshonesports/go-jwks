package authorizer

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

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

// Authorizer is an http.Handler that authenticates HTTP requests.
type Authorizer struct {
	keys jwks.JSONWebKeySet
	next http.Handler

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
}

// New creates a new Authorizer with an http.Handler.
func New(ks jwks.JSONWebKeySet, handler http.Handler, options ...Option) *Authorizer {
	authorizer := &Authorizer{
		keys: ks,
		next: handler,
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

func (a *Authorizer) validate(authorizationHeader string) (map[string]interface{}, error) {
	if authorizationHeader == "" {
		return nil, ErrMissingHeader
	}

	if !strings.HasPrefix(authorizationHeader, "Bearer ") {
		return nil, ErrInvalidHeader
	}

	claims := make(jwt.MapClaims)
	if _, err := jwt.ParseWithClaims(authorizationHeader[7:], claims, a.keyfunc); err != nil {
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

// ServerHTTP authenticates the HTTP request.
func (a *Authorizer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	header := a.Header
	if header == "" {
		header = defaultHeader
	}

	claims, err := a.validate(r.Header.Get(header))
	a.next.ServeHTTP(w, r.WithContext(withResult(r.Context(), claims, err)))
}

// ErrorHandler returns a http.Handler that handles authorizer errors.
func ErrorHandler(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
	}
}

// ErrorHandlerFunc is the same as ErrorHandler for http.HandlerFunc.
func ErrorHandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return ErrorHandler(next)
}
