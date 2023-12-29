package secure

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"embed"
	"errors"
	"fmt"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

const (
	KEY_TYPE_RSA     = "rsa"
	KEY_TYPE_ECDSA   = "ecdsa"
	KEY_TYPE_ED25519 = "ed25519"
)

type KeyInfo struct {
	Type    string
	BitSize []int
}

var SupportedKeyTypes = []KeyInfo{
	{
		Type:    KEY_TYPE_RSA,
		BitSize: []int{1024, 2048, 3072},
	},
	{
		Type:    KEY_TYPE_ECDSA,
		BitSize: []int{256, 384, 521},
	},
	{
		Type:    KEY_TYPE_ED25519,
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
		return nil, err
	}

	switch eKey := key.(type) {
	case *ecdsa.PrivateKey:
		return eKey, nil
	case *ed25519.PrivateKey:
		return *eKey, nil
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

type KeyWithFilter struct {
	Key    []byte
	Filter string
}

var ErrPubKeyNotFound = errors.New("public key not found")

func (key KeyWithFilter) GetKey() ([]byte, error) {
	for _, l := range splitIntoLines(key.Key) {
		if strings.Contains(l, key.Filter) {
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

func EncryptSharedSecret(aesKey []byte, pub crypto.PublicKey) ([]byte, error) { //nolint: cyclop
	private, err := FindPrvSharedKey(pub)
	if err != nil {
		return nil, err
	}

	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		prv, err := private.(*ecdsa.PrivateKey).ECDH()
		if err != nil {
			return nil, err
		}

		public, err := key.ECDH()
		if err != nil {
			return nil, err
		}

		secret, err := prv.ECDH(public)
		if err != nil {
			return nil, err
		}

		return EncryptAES(secret, aesKey, 0)

	case ed25519.PublicKey:
		xPrv := ed25519PrivateKeyToCurve25519(private.(ed25519.PrivateKey))
		xPub, err := ed25519PublicKeyToCurve25519(pub.(ed25519.PublicKey))
		if err != nil {
			return nil, err
		}

		secret, err := curve25519.X25519(xPrv, xPub)
		if err != nil {
			return nil, err
		}

		return EncryptAES(secret, aesKey, 0)

	case *rsa.PublicKey:
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, key, aesKey, nil)

	default:
		return nil, fmt.Errorf("%w, got: %T", ErrNotSupportedKey, pub)
	}
}

func DecryptSharedSecret(encryptedAESKey []byte, prv crypto.PrivateKey) ([]byte, error) { //nolint: cyclop
	public, err := FindPubSharedKey(prv)
	if err != nil {
		return nil, err
	}

	switch key := prv.(type) {
	case *ecdsa.PrivateKey:
		private, err := key.ECDH()
		if err != nil {
			return nil, err
		}

		pub, err := public.(*ecdsa.PublicKey).ECDH()
		if err != nil {
			return nil, err
		}

		secret, err := private.ECDH(pub)
		if err != nil {
			return nil, err
		}

		return DecryptAES(secret, encryptedAESKey, 0)

	case ed25519.PrivateKey:
		xPrv := ed25519PrivateKeyToCurve25519(key)
		xPub, err := ed25519PublicKeyToCurve25519(public.(ed25519.PublicKey))
		if err != nil {
			return nil, err
		}

		secret, err := curve25519.X25519(xPrv, xPub)
		if err != nil {
			return nil, err
		}

		return DecryptAES(secret, encryptedAESKey, 0)

	case *rsa.PrivateKey:
		return rsa.DecryptOAEP(sha256.New(), rand.Reader, key, encryptedAESKey, nil)

	default:
		return nil, fmt.Errorf("%w, got: %T", ErrNotSupportedKey, prv)
	}
}

func PublicKeySize(pub crypto.PublicKey) int {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return key.Params().BitSize
	case ed25519.PublicKey:
		return len(key) * 8
	case *rsa.PublicKey:
		return key.N.BitLen()
	default:
		return 0
	}
}

func PrivateKeySize(prv crypto.PrivateKey) int {
	switch key := prv.(type) {
	case *ecdsa.PrivateKey:
		return key.Params().BitSize
	case ed25519.PrivateKey:
		return len(key.Seed()) * 8
	case *rsa.PrivateKey:
		return key.N.BitLen()
	default:
		return 0
	}
}

//go:embed shared-keys
var sharedKeys embed.FS

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
		return nil, fmt.Errorf("%w, got: %T", ErrPubKeyNotFound, prv)
	}

	b, err := sharedKeys.ReadFile(file)
	if err != nil {
		return nil, err
	}

	return SSHPubKey(b)
}

var ErrPrvKeyNotFound = errors.New("private key not found")

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
		return nil, fmt.Errorf("%w, got: %T", ErrPrvKeyNotFound, pub)
	}

	b, err := sharedKeys.ReadFile(file)
	if err != nil {
		return nil, err
	}

	return SSHPrvKey(b, "")
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

const PUBLIC_KEY_ID_SIZE = 8

func PublicKeyID(pub crypto.PublicKey) []byte {
	h := md5.New()
	var d []byte

	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		d = h.Sum(append(key.X.Bytes(), key.Y.Bytes()...))
	case ed25519.PublicKey:
		d = h.Sum(key)
	case *rsa.PublicKey:
		d = h.Sum(key.N.Bytes())
	}

	return d[:PUBLIC_KEY_ID_SIZE]
}

func PublicKeyIDByPrivateKey(prv crypto.PrivateKey) []byte {
	return PublicKeyID(prv.(crypto.Signer).Public())
}
