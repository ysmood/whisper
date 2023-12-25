package secure

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

var ErrNotSupportedKey = errors.New("not an supported key")

func SSHPubKey(publicKey []byte) (crypto.PublicKey, error) {
	for len(publicKey) > 0 {
		var key ssh.PublicKey
		var err error

		key, _, _, publicKey, err = ssh.ParseAuthorizedKey(publicKey)
		if err != nil {
			return nil, err
		}

		switch eKey := key.(ssh.CryptoPublicKey).CryptoPublicKey().(type) {
		case *ecdsa.PublicKey:
			return eKey, nil
		case *rsa.PublicKey:
			return eKey, nil
		case ed25519.PublicKey:
			return eKey, nil
		default:
			continue
		}
	}

	return nil, fmt.Errorf("%w, can't find public key", ErrNotSupportedKey)
}

// SSHKey returns a private key from a ssh private key.
func SSHKey(keyData []byte, passphrase string) (crypto.PrivateKey, error) {
	var key interface{}
	var err error
	if passphrase == "" {
		key, err = ssh.ParseRawPrivateKey(keyData)
	} else {
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(keyData, []byte(passphrase))
	}
	if err != nil {
		return nil, err
	}

	switch eKey := key.(type) {
	case *ecdsa.PrivateKey:
		return eKey, nil
	case *rsa.PrivateKey:
		return eKey, nil
	case *ed25519.PrivateKey:
		return *eKey, nil
	default:
		return nil, fmt.Errorf("%w, got: %T", ErrNotSupportedKey, key)
	}
}

func IsAuthErr(err error) bool {
	missingErr := &ssh.PassphraseMissingError{}
	return errors.Is(err, x509.IncorrectPasswordError) || err.Error() == missingErr.Error()
}
