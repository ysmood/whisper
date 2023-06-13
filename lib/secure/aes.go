package secure

import (
	"bytes"
	"io"

	"github.com/ysmood/whisper/lib/piper"
)

func EncryptAES(key string, data []byte) ([]byte, error) {
	encrypted := bytes.NewBuffer(nil)

	enc, err := piper.NewAES([]byte(key)).Encoder(encrypted)
	if err != nil {
		return nil, err
	}

	_, err = enc.Write(data)
	if err != nil {
		return nil, err
	}

	return encrypted.Bytes(), nil
}

func DecryptAES(key string, data []byte) ([]byte, error) {
	decrypted, err := piper.NewAES([]byte(key)).Decoder(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	return io.ReadAll(decrypted)
}
