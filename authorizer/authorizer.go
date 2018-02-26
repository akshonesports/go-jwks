package authorizer

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/akshonesports/go-jwks"
	"github.com/dgrijalva/jwt-go"
)

// Config is the options for an Authorizer.
type Config struct {
	// Audience is the expected token audience
	//
	// If this value is not empty, authorization will fail if the token
	// audience does not match this value.
	Audience string

	// Issuer is the expected token issuer.
	//
	// If this value is not empty, authorization will fail if the token issuer
	// does not match this value.
	Issuer string

	// Algorithms is a whitelist of algorithms used to verify a token.
	//
	// If this value is not empty, authorization will fail if the token
	// algorithm is not one the whitelisted values.
	Algorithms []jwks.Algorithm

	// Keys is the set of JWKs.
	Keys jwks.JSONWebKeySet
}

// Authorizer is an http.Handler that authenticates HTTP requests.
type Authorizer struct {
	config Config
	next   http.Handler
}

// New creates a new Authorizer with an http.Handler.
func New(config Config, handler http.Handler) *Authorizer {
	return &Authorizer{
		config: config,
		next:   handler,
	}
}

// New creates a new Authorizer with an http.HandlerFunc.
func NewFunc(config Config, handler http.HandlerFunc) *Authorizer {
	return &Authorizer{
		config: config,
		next:   handler,
	}
}

func (a *Authorizer) keyfunc(token *jwt.Token) (interface{}, error) {
	kid, ok := token.Header["kid"]
	if !ok {
		return nil, errors.New("missing key id")
	}

	keyID, ok := kid.(string)
	if !ok {
		return nil, errors.New("invalid key id")
	}

	if a.config.Keys == nil {
		return nil, errors.New("unknown key id")
	}

	key, ok := a.config.Keys[keyID]
	if !ok {
		return nil, errors.New("unknown key id")
	}

	if len(a.config.Algorithms) == 0 {
		return key.Key, nil
	}

	alg, ok := token.Header["alg"]
	if !ok {
		return nil, errors.New("missing algorithm value")
	}

	algorithm, ok := alg.(string)
	if !ok {
		return nil, errors.New("invalid algorithm value")
	}

	for _, algo := range a.config.Algorithms {
		if string(algo) == algorithm {
			return key.Key, nil
		}
	}

	return nil, errors.New("algorithm not allowed")
}

// ServerHTTP authenticates the HTTP request.
func (a *Authorizer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authorizationHeader := r.Header.Get("Authorization")
	if authorizationHeader == "" {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	if !strings.HasPrefix(authorizationHeader, "Bearer ") {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	var claims jwt.StandardClaims
	if _, err := jwt.ParseWithClaims(authorizationHeader[7:], &claims, a.keyfunc); err != nil {
		goto Unauthorized
	}

	if a.config.Issuer != "" && claims.Issuer != a.config.Issuer {
		// fmt.Println("invalid issuer")
		goto Unauthorized
	}

	if a.config.Audience != "" && claims.Audience != a.config.Audience {
		// fmt.Println("invalid audience")
		goto Unauthorized
	}

	if time.Unix(claims.IssuedAt, 0).After(time.Now()) {
		// fmt.Println("token not valid yet")
		goto Unauthorized
	}

	if time.Unix(claims.ExpiresAt, 0).Before(time.Now()) {
		// fmt.Println("token expired")
		goto Unauthorized
	}

	a.next.ServeHTTP(w, r)
	return

Unauthorized:
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
