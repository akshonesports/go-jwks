package jwks

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/akshonesports/go-jwks/internal/decoder"
	"github.com/akshonesports/go-jwks/internal/decoder/ec"
	"github.com/akshonesports/go-jwks/internal/decoder/octet"
	"github.com/akshonesports/go-jwks/internal/decoder/rsa"
)

// KeyType is a type of key.
type KeyType string

// KeyType values as defined in RFC7518§6.1 (https://tools.ietf.org/html/rfc7518#section-6.1).
const (
	EllipticCurve KeyType = "EC"
	RSA           KeyType = "RSA"
	OctetSequence KeyType = "oct"
)

// PublicKeyUse is the intended usage of the key.
type PublicKeyUse string

// PublicKeyUse values as defined in RFC7517§4.2 (https://tools.ietf.org/html/rfc7517#section-4.2).
const (
	Signature  PublicKeyUse = "sig"
	Encryption PublicKeyUse = "enc"
)

// KeyOperation is the intended operation the key is to be used for.
type KeyOperation string

// KeyOperation values as defined in RFC7517§4.3 (https://tools.ietf.org/html/rfc7517#section-4.3).
const (
	Sign           KeyOperation = "sign"
	Verify         KeyOperation = "verify"
	EncryptContent KeyOperation = "encrypt"
	DecryptContent KeyOperation = "decrypt"
	EncryptKey     KeyOperation = "wrapKey"
	DecryptKey     KeyOperation = "unwrapKey"
	DeriveKey      KeyOperation = "deriveKey"
	DeriveBits     KeyOperation = "deriveBits"
)

// Algorithm is the intended algorithm the key is to be used with.
type Algorithm string

// Algorithm values as defined in RFC7518§3.1 (https://tools.ietf.org/html/rfc7518#section-3.1).
const (
	HS256 Algorithm = "HS256" // HMAC using SHA-256 (Required).
	HS384 Algorithm = "HS384" // HMAC using SHA-384 (Optional).
	HS512 Algorithm = "HS512" // HMAC using SHA-512 (Optional).
	RS256 Algorithm = "RS256" // RSASSA-PKCS1-v1_5 using SHA-256 (Recommended).
	RS384 Algorithm = "RS384" // RSASSA-PKCS1-v1_5 using SHA-384 (Optional).
	RS512 Algorithm = "RS512" // RSASSA-PKCS1-v1_5 using SHA-512 (Optional).
	ES256 Algorithm = "ES256" // ECDSA using P-256 and SHA-256 (Recommended+).
	ES384 Algorithm = "ES384" // ECDSA using P-384 and SHA-384 (Optional).
	ES512 Algorithm = "ES512" // ECDSA using P-521 and SHA-512 (Optional).
	PS256 Algorithm = "PS256" // RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (Optional).
	PS384 Algorithm = "PS384" // RSASSA-PSS using SHA-384 and MGF1 with SHA-384 (Optional).
	PS512 Algorithm = "PS512" // RSASSA-PSS using SHA-512 and MGF1 with SHA-512 (Optional).
	None  Algorithm = "none"  // No digital signature or MAC performed (Optional).
)

type keyInfo struct {
	KeyType                         KeyType      `json:"kty"`
	PublicKeyUse                    PublicKeyUse `json:"use,omitempty"`
	KeyOperations                   KeyOperation `json:"key_ops,omitempty"`
	Algorithm                       Algorithm    `json:"alg,omitempty"`
	KeyID                           string       `json:"kid,omitempty"`
	X509URL                         string       `json:"x5u,omitempty"`
	X509CertificateChain            []string     `json:"x5c,omitempty"`
	X509CertificateSHA1Thumbprint   string       `json:"x5t,omitempty"`
	X509CertificateSHA256Thumbprint string       `json:"x5t#256,omitempty"`
}

// JSONWebKey holds information about a key as well as the key itself.
type JSONWebKey struct {
	keyInfo

	Key interface{}
}

// UnmarshalJSON decodes the data as a JSON encoded string.
func (k *JSONWebKey) UnmarshalJSON(data []byte) (err error) {
	if err := json.Unmarshal(data, &k.keyInfo); err != nil {
		return err
	}

	if k.KeyType == "" {
		return fmt.Errorf(`key "%s" is missing "kty" property`, k.KeyID)
	}

	var dec decoder.JWKDecoder
	switch k.KeyType {
	case RSA:
		dec = rsa.Decoder
	case EllipticCurve:
		dec = ec.Decoder
	case OctetSequence:
		dec = octet.Decoder
	default:
		return fmt.Errorf(`key "%s" has unsupported key type "%s"`, k.KeyID, k.KeyType)
	}

	if k.Key, err = dec.DecodeKey(data); err != nil {
		return err
	}

	return nil
}

// JSONWebKeySet holds a set of JSONWebKeys and a lookup table for quick access.
type JSONWebKeySet map[string]*JSONWebKey

func generateLookupTable(keys []*JSONWebKey) JSONWebKeySet {
	jwks := make(JSONWebKeySet)
	for _, k := range keys {
		jwks[k.KeyID] = k
	}

	return jwks
}

// Key returns the key with a matching key id.
func (s JSONWebKeySet) Key(keyID string) (*JSONWebKey, error) {
	key, ok := s[keyID]
	if !ok {
		return nil, errors.New("no such key")
	}

	return key, nil
}

// FromURL makes an HTTP request to the given url and decodes the response body as a JWK Set.
func FromURL(url string) (JSONWebKeySet, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %v", err)
	}

	defer resp.Body.Close()

	return FromReader(resp.Body)
}

// FromReader decodes the data from the given reader as a JWK Set.
func FromReader(reader io.Reader) (JSONWebKeySet, error) {
	var keyList struct {
		Keys []*JSONWebKey `json:"keys"`
	}
	if err := json.NewDecoder(reader).Decode(&keyList); err != nil {
		return nil, fmt.Errorf("failed to parse data: %v", err)
	}

	return generateLookupTable(keyList.Keys), nil
}
