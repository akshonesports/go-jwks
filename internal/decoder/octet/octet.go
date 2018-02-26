package octet

import (
	"encoding/base64"
	"errors"

	"github.com/akshonesports/go-jwks/internal/decoder"
)

var Decoder decoder.JWKDecoder = (*dec)(nil)

type dec struct{}

func (*dec) DecodeKey(data []byte) (interface{}, error) {
	var params struct {
		K string `json:"k"`
	}

	if params.K == "" {
		return nil, errors.New("invalid octet key")
	}

	keyData, err := base64.RawURLEncoding.DecodeString(params.K)
	if err != nil {
		return nil, err
	}

	return keyData, nil
}
