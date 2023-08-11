package secure

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

var ErrNotECDSAKey = errors.New("not an ECDSA key")

func SSHPubKey(publicKey []byte) (*ecdsa.PublicKey, error) {
	for len(publicKey) > 0 {
		var key ssh.PublicKey
		var err error

		key, _, _, publicKey, err = ssh.ParseAuthorizedKey(publicKey)
		if err != nil {
			return nil, err
		}

		eKey, ok := key.(ssh.CryptoPublicKey).CryptoPublicKey().(*ecdsa.PublicKey)
		if !ok {
			continue
		}

		return eKey, nil
	}

	return nil, fmt.Errorf("%w, can't find public key", ErrNotECDSAKey)
}

// SSHKey returns a private key from a ssh private key.
func SSHKey(keyData []byte, passphrase string) (*ecdsa.PrivateKey, error) {
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

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w, got: %T", ErrNotECDSAKey, key)
	}

	return ecKey, nil
}

func IsAuthErr(err error) bool {
	missingErr := &ssh.PassphraseMissingError{}
	return errors.Is(err, x509.IncorrectPasswordError) || err.Error() == missingErr.Error()
}
