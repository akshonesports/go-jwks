# go-jwks

`go-jwks` reads signing keys from a [JWK Set](https://tools.ietf.org/html/rfc7517#section-5) endpoint.

## Usage

JWK Sets may be retrieved from a URL endpoint:

```
keySet, err := jwks.FromURL("https://example.auth0.com/.well-known/jwks.json")
```

Or directly from a `io.Reader`:

```
file, err := os.Open("path/to/jwks.json")
keySet, err := jwks.FromReader(file)
```

### Accessing Keys

Once a JWK Set is retrieved, a JWK may be accessed by passing a keyID:

```
jwk, err := keySet.Key(keyID)

// OR

jwk, ok := keySet[keyID]
```

The raw key is also available (be sure it is the correct type):

```
rsaKey, ok := jwk.Key.(*rsa.PublicKey)
if !ok {
	fmt.Println("wrong key type")
}
```
```
ecKey, ok := jwk.Key.(*ecdsa.PublicKey)
if !ok {
	fmt.Println("wrong key type")
}
```
```
octetKey, ok := jwk.Key.([]byte)
if !ok {
	fmt.Println("wrong key type")
}
```

### HTTP Middleware

An HTTP Middleware is included for simple request authorization.

```
http.ListenAndServe("", authorizer.New(keys, authorizer.ErrorHandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello", authorizer.Claims(r.Context())["sub"])
})))
```

or you can handle the authorization errors yourself:

```
http.ListenAndServe("", authorizer.Func(keys, func(w http.ResponseWriter, r *http.Request) {
	if err := authorizer.Error(r.Context()); err != nil {
		http.Error(w, "You're not allowed! >:[", http.StatusUnauthorized)
		return
	}

	fmt.Fprintln(w, "Hello", authorizer.Claims(r.Context())["sub"])
}))
```
