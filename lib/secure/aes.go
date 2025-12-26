package secure

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ysmood/whisper/lib/piper"
)

func EncryptAES(key, data []byte, guard int) ([]byte, error) {
	encrypted := bytes.NewBuffer(nil)

	enc, err := piper.NewAES(key, guard).Encoder(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES encoder: %w", err)
	}

	_, err = enc.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write data to AES encoder: %w", err)
	}

	return encrypted.Bytes(), nil
}

func DecryptAES(key, data []byte, guard int) ([]byte, error) {
	decrypted, err := piper.NewAES(key, guard).Decoder(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create AES decoder: %w", err)
	}

	result, err := io.ReadAll(decrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}
	return result, nil
}
