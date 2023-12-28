package whisper

import (
	"bufio"
	"bytes"
	"encoding/json"
)

func encode(data any) (res []byte, err error) {
	return json.Marshal(data)
}

func decode[T any](data []byte) (res T, err error) {
	return res, json.Unmarshal(data, &res)
}

func selectPublicKeys(keys []PublicKey) ([][]byte, error) {
	res := make([][]byte, len(keys))
	for i, key := range keys {
		data, err := key.Select()
		if err != nil {
			return nil, err
		}
		res[i] = data
	}
	return res, nil
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
