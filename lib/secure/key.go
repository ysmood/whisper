package secure

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

var ErrNotSupportedKey = errors.New("not an supported key")

func SSHPubKey(publicKey []byte) (crypto.PublicKey, error) {
	for len(publicKey) > 0 {
		var key ssh.PublicKey
		var err error

		key, _, _, publicKey, err = ssh.ParseAuthorizedKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}

		switch eKey := key.(ssh.CryptoPublicKey).CryptoPublicKey().(type) {
		case *ecdsa.PublicKey:
			return eKey, nil
		case ed25519.PublicKey:
			return eKey, nil
		case *rsa.PublicKey:
			return eKey, nil
		default:
			continue
		}
	}

	return nil, fmt.Errorf("%w, can't find public key", ErrNotSupportedKey)
}

// SSHPrvKey returns a private key from a ssh private key.
func SSHPrvKey(keyData []byte, passphrase string) (crypto.PrivateKey, error) {
	var key interface{}
	var err error
	if passphrase == "" {
		key, err = ssh.ParseRawPrivateKey(keyData)
	} else {
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(keyData, []byte(passphrase))
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	var prv crypto.PrivateKey

	switch eKey := key.(type) {
	case *ecdsa.PrivateKey:
		prv = eKey
	case *ed25519.PrivateKey:
		prv = *eKey
	case *rsa.PrivateKey:
		prv = eKey
	default:
		return nil, fmt.Errorf("%w, got: %T", ErrNotSupportedKey, key)
	}

	return prv, nil
}

// Belongs checks if pub key belongs to prv key.
func Belongs(pub, prv []byte, passphrase string) (bool, error) {
	prvKey, err := SSHPrvKey(prv, passphrase)
	if err != nil {
		return false, err
	}

	pubKey, err := SSHPubKey(pub)
	if err != nil {
		return false, err
	}

	switch key := pubKey.(type) {
	case *ecdsa.PublicKey:
		return prvKey.(*ecdsa.PrivateKey).PublicKey.Equal(key), nil
	case ed25519.PublicKey:
		return bytes.Equal(prvKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey), key), nil
	case *rsa.PublicKey:
		return prvKey.(*rsa.PrivateKey).PublicKey.Equal(key), nil
	}

	return false, nil
}

func IsAuthErr(err error) bool {
	missingErr := &ssh.PassphraseMissingError{}
	return errors.Is(err, x509.IncorrectPasswordError) || errors.As(err, &missingErr)
}

// ed25519PrivateKeyToCurve25519 converts a ed25519 private key in X25519 equivalent
// source: https://github.com/FiloSottile/age/blob/980763a16e30ea5c285c271344d2202fcb18c33b/agessh/agessh.go#L287
func ed25519PrivateKeyToCurve25519(pk ed25519.PrivateKey) []byte {
	h := sha512.New()
	h.Write(pk.Seed())
	out := h.Sum(nil)
	return out[:curve25519.ScalarSize]
}

// ed25519PublicKeyToCurve25519 converts a ed25519 public key in X25519 equivalent
// source: https://github.com/FiloSottile/age/blob/main/agessh/agessh.go#L190
func ed25519PublicKeyToCurve25519(pk ed25519.PublicKey) ([]byte, error) {
	// See https://blog.filippo.io/using-ed25519-keys-for-encryption and
	// https://pkg.go.dev/filippo.io/edwards25519#Point.BytesMontgomery.
	p, err := new(edwards25519.Point).SetBytes(pk)
	if err != nil {
		return nil, err
	}
	return p.BytesMontgomery(), nil
}
