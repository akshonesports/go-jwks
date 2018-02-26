package decoder

type JWKDecoder interface {
	DecodeKey(data []byte) (interface{}, error)
}
