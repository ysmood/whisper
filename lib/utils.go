package whisper

import (
	"encoding/base64"
	"encoding/json"

	"github.com/ysmood/whisper/lib/secure"
)

var Base64Encoding = base64.RawURLEncoding

func encode(data any) (res []byte, err error) {
	return json.Marshal(data)
}

func decode[T any](data []byte) (res T, err error) {
	return res, json.Unmarshal(data, &res)
}

func toKeyWithFilters(keys [][]byte) []secure.KeyWithFilter {
	res := make([]secure.KeyWithFilter, len(keys))
	for i, key := range keys {
		res[i] = secure.KeyWithFilter{Key: key}
	}
	return res
}
