package secure

import (
	"crypto/ecdh"
	"crypto/x509"
	"io"
)

type Key interface {
	Generate() (aesKey []byte, encryptedKey []byte, err error)
	Decrypt(encryptedKey []byte) (aesKey []byte, err error)
}

// Encrypt a data stream with a private key and AES.
func Encrypt(key Key, encrypted io.Writer) (io.WriteCloser, error) {
	aesKey, encryptedKey, err := key.Generate()
	if err != nil {
		return nil, err
	}

	_, err = encrypted.Write(encryptedKey)
	if err != nil {
		return nil, err
	}

	return NewAESEncrypter(aesKey, encrypted)
}

// Decrypt a data stream with a private key and AES.
func Decrypt(key Key, encrypted io.Reader) (io.Reader, error) {
	encryptedKey := make([]byte, 32)

	_, err := io.ReadFull(encrypted, encryptedKey)
	if err != nil {
		return nil, err
	}

	aesKey, err := key.Decrypt(encryptedKey)
	if err != nil {
		return nil, err
	}

	return NewAESDecrypter(aesKey, encrypted)
}

// LoadPublicKey from binary.
func LoadPublicKey(keyData []byte) (Key, error) {
	data, err := x509.ParsePKIXPublicKey(keyData)
	if err != nil {
		return nil, err
	}

	return &KeyECDH{
		pub: data.(*ecdh.PublicKey),
	}, nil
}

// LoadPrivateKey from binary.
func LoadPrivateKey(passphrase string, keyData []byte) (Key, error) {
	keyData, err := DecryptAES(passphrase, keyData)
	if err != nil {
		return nil, err
	}

	k, err := x509.ParsePKCS8PrivateKey(keyData)
	if err != nil {
		return nil, err
	}

	return &KeyECDH{
		key: k.(*ecdh.PrivateKey),
	}, nil
}
