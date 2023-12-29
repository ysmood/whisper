package whisper

import (
	"bufio"
	"bytes"
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

func toPublicKey(keys [][]byte) []PublicKey {
	res := make([]PublicKey, len(keys))
	for i, key := range keys {
		res[i] = PublicKey{Data: key}
	}
	return res
}

func splitIntoLines(text []byte) []string {
	scanner := bufio.NewScanner(bytes.NewReader(text))
	scanner.Split(bufio.ScanLines)

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines
}
