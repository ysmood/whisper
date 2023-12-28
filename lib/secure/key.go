package secure

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

type KeyInfo struct {
	Type    string
	BitSize []int
}

var SupportedKeyTypes = []KeyInfo{
	{
		Type:    "rsa",
		BitSize: []int{1024, 2048, 3072},
	},
	{
		Type:    "ecdsa",
		BitSize: []int{256, 384, 521},
	},
	{
		Type:    "ed25519",
		BitSize: []int{256},
	},
}

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

func PrivateKeyTypePrefix(key crypto.PrivateKey) string {
	switch key.(type) {
	case *ecdsa.PrivateKey:
		return "ecdsa-sha2-nistp256"
	case *rsa.PrivateKey:
		return "ssh-rsa"
	case ed25519.PrivateKey:
		return "ssh-ed25519"
	}

	return "unknown"
}

// Belongs checks if pub key belongs to prv key.
func Belongs(pub KeyWithFilter, prv []byte, passphrase string) bool {
	prvKey, err := SSHPrvKey(prv, passphrase)
	if err != nil {
		return false
	}

	key, err := pub.GetKey(PrivateKeyTypePrefix(prvKey))
	if err != nil {
		return false
	}

	pubKey, err := SSHPubKey(key)
	if err != nil {
		return false
	}

	switch key := pubKey.(type) {
	case *ecdsa.PublicKey:
		return prvKey.(*ecdsa.PrivateKey).PublicKey.Equal(key)
	case *rsa.PublicKey:
		return prvKey.(*rsa.PrivateKey).PublicKey.Equal(key)
	case ed25519.PublicKey:
		return bytes.Equal(prvKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey), key)
	}

	return false
}

type KeyWithFilter struct {
	Key    []byte
	Filter string
}

var ErrPubKeyNotFound = errors.New("public key not found")

func (key KeyWithFilter) GetKey(typePrefix string) ([]byte, error) {
	for _, l := range splitIntoLines(key.Key) {
		if strings.HasPrefix(l, typePrefix) && strings.Contains(l, key.Filter) {
			return []byte(l), nil
		}
	}

	return nil, fmt.Errorf("%w with filter: %s", ErrPubKeyNotFound, key.Filter)
}

func splitIntoLines(text []byte) []string {
	scanner := bufio.NewScanner(bytes.NewReader(text))
	scanner.Split(bufio.ScanLines)

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines
}

func SharedSecret(prv crypto.PrivateKey, pub crypto.PublicKey) ([]byte, error) {
	switch key := prv.(type) {
	case *ecdsa.PrivateKey:
		private, err := key.ECDH()
		if err != nil {
			return nil, err
		}

		public, err := pub.(*ecdsa.PublicKey).ECDH()
		if err != nil {
			return nil, err
		}

		return private.ECDH(public)
	case ed25519.PrivateKey:
		xPriv := ed25519PrivateKeyToCurve25519(key)
		xPub, err := ed25519PublicKeyToCurve25519(pub.(ed25519.PublicKey))
		if err != nil {
			return nil, err
		}

		return curve25519.X25519(xPriv, xPub)

	default:
		return nil, fmt.Errorf("%w, got: %T", ErrNotSupportedKey, prv)
	}
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
