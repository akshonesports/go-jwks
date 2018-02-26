package rsa

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"

	"github.com/akshonesports/go-jwks/internal/decoder"
)

var Decoder decoder.JWKDecoder = (*dec)(nil)

type dec struct{}

func (*dec) DecodeKey(data []byte) (interface{}, error) {
	var params struct {
		N string `json:"n"`
		E string `json:"e"`
	}

	if err := json.Unmarshal(data, &params); err != nil {
		return nil, err
	}

	if params.N == "" || params.E == "" {
		return nil, errors.New("invalid rsa parameters")
	}

	var key rsa.PublicKey

	modulusBytes, err := base64.RawURLEncoding.DecodeString(params.N)
	if err != nil {
		return nil, err
	}

	key.N = (&big.Int{}).SetBytes(modulusBytes)

	exponentBytes, err := base64.RawURLEncoding.DecodeString(params.E)
	if err != nil {
		return nil, err
	}

	for missing := 4 - len(exponentBytes); missing > 0; missing-- {
		exponentBytes = append([]byte{0}, exponentBytes...)
	}

	key.E = int(binary.BigEndian.Uint32(exponentBytes))

	return &key, nil
}
