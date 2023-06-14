package secure

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
)

func GenKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenKeys generate a pair of keys in base64 format.
func GenKeys(passphrase string) (public []byte, private []byte, err error) {
	key, err := GenKey()
	if err != nil {
		return
	}

	private, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}

	private, err = EncryptAES(passphrase, private)
	if err != nil {
		return
	}

	public, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return
	}

	return
}
