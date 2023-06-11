package secure

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"io"
)

// NewAESEncrypter creates a new AESEncrypter.
func NewAESEncrypter(key []byte, encrypted io.Writer) (io.WriteCloser, error) {
	hashedKey := md5.Sum(key)
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}

	_, err = encrypted.Write(iv)
	if err != nil {
		return nil, err
	}

	return &cipher.StreamWriter{
		S: cipher.NewOFB(block, iv),
		W: encrypted,
	}, nil
}

// NewAESEncrypter creates a new AESEncrypter.
func NewAESDecrypter(key []byte, encrypted io.Reader) (io.Reader, error) {
	hashedKey := md5.Sum(key)
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(encrypted, iv)
	if err != nil {
		return nil, err
	}

	return &cipher.StreamReader{
		S: cipher.NewOFB(block, iv),
		R: encrypted,
	}, nil
}

func EncryptAES(key string, data []byte) ([]byte, error) {
	encrypted := bytes.NewBuffer(nil)

	enc, err := NewAESEncrypter([]byte(key), encrypted)
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
	decrypted, err := NewAESDecrypter([]byte(key), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	return io.ReadAll(decrypted)
}
