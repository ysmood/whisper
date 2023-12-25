package secure

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

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
