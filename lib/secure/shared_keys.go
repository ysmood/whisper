package secure

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"embed"
	"fmt"
)

//go:embed shared-keys
var embeddedSharedKeys embed.FS

func FindPubSharedKey(prv crypto.PrivateKey) (crypto.PublicKey, error) {
	size := PrivateKeySize(prv)

	var file string

	switch prv.(type) {
	case *ecdsa.PrivateKey:
		file = fmt.Sprintf("shared-keys/id_%s_%d.pub", KEY_TYPE_ECDSA, size)
	case ed25519.PrivateKey:
		file = fmt.Sprintf("shared-keys/id_%s_%d.pub", KEY_TYPE_ED25519, size)
	case *rsa.PrivateKey:
		file = fmt.Sprintf("shared-keys/id_%s_%d.pub", KEY_TYPE_RSA, size)
	default:
		return nil, fmt.Errorf("%w, got: %T", ErrNotSupportedKey, prv)
	}

	b, err := embeddedSharedKeys.ReadFile(file)
	if err != nil {
		return nil, err
	}

	return SSHPubKey(b)
}

func FindPrvSharedKey(pub crypto.PublicKey) (crypto.PrivateKey, error) {
	size := PublicKeySize(pub)

	var file string

	switch pub.(type) {
	case *ecdsa.PublicKey:
		file = fmt.Sprintf("shared-keys/id_%s_%d", KEY_TYPE_ECDSA, size)
	case ed25519.PublicKey:
		file = fmt.Sprintf("shared-keys/id_%s_%d", KEY_TYPE_ED25519, size)
	case *rsa.PublicKey:
		file = fmt.Sprintf("shared-keys/id_%s_%d", KEY_TYPE_RSA, size)
	default:
		return nil, fmt.Errorf("%w, got: %T", ErrNotSupportedKey, pub)
	}

	b, err := embeddedSharedKeys.ReadFile(file)
	if err != nil {
		return nil, err
	}

	return SSHPrvKey(b, "")
}
