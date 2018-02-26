package ec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/akshonesports/go-jwks/internal/decoder"
)

var Decoder decoder.JWKDecoder = (*dec)(nil)

type dec struct{}

func (*dec) DecodeKey(data []byte) (interface{}, error) {
	var params struct {
		Curve string `json:"crv"`
		X     string `json:"x"`
		Y     string `json:"y"`
	}

	var key ecdsa.PublicKey

	switch params.Curve {
	case "P-224":
		key.Curve = elliptic.P224()
	case "P-256":
		key.Curve = elliptic.P256()
	case "P-384":
		key.Curve = elliptic.P384()
	case "P-521":
		key.Curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", params.Curve)
	}

	if err := json.Unmarshal(data, &params); err != nil {
		return nil, err
	}

	if params.X == "" || params.Y == "" {
		return nil, errors.New("invalid ec parameters")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(params.X)
	if err != nil {
		return nil, err
	}

	key.X = (&big.Int{}).SetBytes(xBytes)

	yBytes, err := base64.RawURLEncoding.DecodeString(params.Y)
	if err != nil {
		return nil, err
	}

	key.Y = (&big.Int{}).SetBytes(yBytes)

	return &key, nil
}
