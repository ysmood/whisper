package secure

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
)

// GenKeys generate a pair of keys in base64 format.
func GenKeys(passphrase string) (private []byte, public []byte, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
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

	public, err = x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		return
	}

	return
}
