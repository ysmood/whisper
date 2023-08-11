package whisper

import (
	"encoding/base64"
	"encoding/json"
)

var Base64Encoding = base64.RawURLEncoding

func encode(data any) (res []byte, err error) {
	return json.Marshal(data)
}

func decode[T any](data []byte) (res T, err error) {
	return res, json.Unmarshal(data, &res)
}
