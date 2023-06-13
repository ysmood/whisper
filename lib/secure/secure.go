package secure

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"io"

	"github.com/ysmood/whisper/lib/piper"
)

type ECC struct {
	pub *ecdh.PublicKey
	key *ecdh.PrivateKey
}

func NewECC(publicKey, privateKey []byte, passphrase string) (piper.EncodeDecoder, error) {
	var err error
	var pub interface{}

	if len(publicKey) > 0 {
		pub, err = x509.ParsePKIXPublicKey(publicKey)
		if err != nil {
			return nil, err
		}
	} else {
		pub = (*ecdh.PublicKey)(nil)
	}

	var key interface{}
	if len(privateKey) > 0 {
		keyData, err := DecryptAES(passphrase, privateKey)
		if err != nil {
			return nil, err
		}

		key, err = x509.ParsePKCS8PrivateKey(keyData)
		if err != nil {
			return nil, err
		}
	} else {
		key = (*ecdh.PrivateKey)(nil)
	}

	return &ECC{
		pub: pub.(*ecdh.PublicKey),
		key: key.(*ecdh.PrivateKey),
	}, nil
}

func (e *ECC) Generate() (aesKey []byte, encryptedKey []byte, err error) {
	remoteKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	aesKey, err = remoteKey.ECDH(e.pub)

	return aesKey, remoteKey.PublicKey().Bytes(), err
}

func (e *ECC) Decrypt(encryptedKey []byte) (aesKey []byte, err error) {
	remoteKey, err := ecdh.X25519().NewPublicKey(encryptedKey)
	if err != nil {
		return nil, err
	}

	return e.key.ECDH(remoteKey)
}

func (e *ECC) Encoder(w io.Writer) (io.WriteCloser, error) {
	aesKey, encryptedKey, err := e.Generate()
	if err != nil {
		return nil, err
	}

	_, err = w.Write(encryptedKey)
	if err != nil {
		return nil, err
	}

	return piper.NewAES(aesKey).Encoder(w)
}

func (e *ECC) Decoder(r io.Reader) (io.ReadCloser, error) {
	encryptedKey := make([]byte, 32)

	_, err := io.ReadFull(r, encryptedKey)
	if err != nil {
		return nil, err
	}

	aesKey, err := e.Decrypt(encryptedKey)
	if err != nil {
		return nil, err
	}

	return piper.NewAES(aesKey).Decoder(r)
}
