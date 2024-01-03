package secure

import (
	"bytes"
	"io"

	"github.com/ysmood/whisper/lib/piper"
)

func EncryptAES(key, data []byte, aesType, guard int) ([]byte, error) {
	encrypted := bytes.NewBuffer(nil)

	enc, err := piper.NewAES(key, aesType, guard).Encoder(encrypted)
	if err != nil {
		return nil, err
	}

	_, err = enc.Write(data)
	if err != nil {
		return nil, err
	}

	return encrypted.Bytes(), nil
}

func DecryptAES(key, data []byte, aesType, guard int) ([]byte, error) {
	decrypted, err := piper.NewAES(key, aesType, guard).Decoder(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	return io.ReadAll(decrypted)
}
