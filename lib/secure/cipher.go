// Package secure makes encrypted data can only be decrypted by selected recipients.
// It allows different types of public keys to secretly exchange data.
//
// # How It Works
//
// Suppose we have a opponent X, append 0 to the upper cased letter we get X0, it represents X's private key,
// similarly X1 represents X's public key.
// Now we have opponents X and Y, they may have different key types, such as X's is rsa, Y's is ecdsa,
// we want to encrypt data D with X and decrypt it with Y. X has access to Y1.
//
// Encryption steps:
//
//	Generate ephemeral key M that has the same key type and size as Y1.
//	Use Y1 and M0 to generate the shared secret key K.
//	Use K to encrypt the D, it generates E.
//	Only send M1 and E to Y.
//
// Decryption steps:
//
//	Use Y0 and M1 to generate the shared secret key K.
//	Use K to decrypt E, we get D.
package secure

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ysmood/byframe/v4"
	"github.com/ysmood/whisper/lib/piper"
	"golang.org/x/crypto/curve25519"
)

const AES_GUARD = 4

// Cipher to encrypt and decrypt data.
// The cipher will generate a random AES secret, each public key will be used to encrypt the AES secret into a key.
// The wire format of the output looks like this:
//
//	[n][key1][key2][key3]...[encrypted-data].
//
// "n" is the number of keys.
// "key1" is the encrypted key for the first public key.
// "key2" is the encrypted key for the second public key.
// ...
// "encrypted-data" is the encrypted data by the AES secret.
type Cipher struct {
	// Default is 16, it can be 16, 24, 32.
	// 16 is AES-128, 24 is AES-192, 32 is AES-256.
	AESType int

	prv crypto.PrivateKey

	index int

	pubs []crypto.PublicKey
}

// NewCipher to encrypt or decrypt data.
// The index indicates which key in the key list is for the prv to decrypt the data.
func NewCipher(prv crypto.PrivateKey, index int, pubs ...crypto.PublicKey) *Cipher {
	return &Cipher{16, prv, index, pubs}
}

func (c *Cipher) Encoder(w io.Writer) (io.WriteCloser, error) {
	aesKey := make([]byte, c.AESType)
	_, err := rand.Read(aesKey)
	if err != nil {
		return nil, err
	}

	encryptedKeys := [][]byte{}
	for _, pub := range c.pubs {
		encrypted, err := EncryptSharedSecret(aesKey, pub)
		if err != nil {
			return nil, err
		}

		encryptedKeys = append(encryptedKeys, encrypted)
	}

	_, err = w.Write(byframe.Encode(byframe.EncodeHeader(len(encryptedKeys))))
	if err != nil {
		return nil, err
	}

	for _, encryptedKey := range encryptedKeys {
		_, err = w.Write(byframe.Encode(encryptedKey))
		if err != nil {
			return nil, err
		}
	}

	return piper.NewAES(aesKey, AES_GUARD).Encoder(w)
}

func (c *Cipher) Decoder(r io.Reader) (io.ReadCloser, error) {
	s := byframe.NewScanner(r)

	header, err := s.Next()
	if err != nil {
		return nil, err
	}

	_, count := byframe.DecodeHeader(header)

	encryptedKeys := [][]byte{}
	for range count {
		encrypted, err := s.Next()
		if err != nil {
			return nil, err
		}
		encryptedKeys = append(encryptedKeys, encrypted)
	}

	aesKey, err := DecryptSharedSecret(encryptedKeys[c.index], c.prv)
	if err != nil {
		return nil, err
	}

	return piper.NewAES(aesKey, AES_GUARD).Decoder(r)
}

var ErrNotRecipient = errors.New("not a recipient, the data is not encrypted for your public key")

func EncryptSharedSecret(sharedKey []byte, pub crypto.PublicKey) ([]byte, error) {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		ephemeral, err := ecdsa.GenerateKey(key.Curve, rand.Reader)
		if err != nil {
			return nil, err
		}

		prv, err := ephemeral.ECDH()
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

		encrypted, err := EncryptAES(secret, sharedKey, 0)
		if err != nil {
			return nil, err
		}

		size := key.Curve.Params().BitSize / 8

		return bytes.Join([][]byte{
			bigIntToBytes(ephemeral.PublicKey.X, size),
			bigIntToBytes(ephemeral.PublicKey.Y, size),
			encrypted,
		}, nil), nil

	case ed25519.PublicKey:
		ephemeralPub, ephemeralPrv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		xPrv := ed25519PrivateKeyToCurve25519(ephemeralPrv)
		xPub, err := ed25519PublicKeyToCurve25519(key)
		if err != nil {
			return nil, err
		}

		secret, err := curve25519.X25519(xPrv, xPub)
		if err != nil {
			return nil, err
		}

		encrypted, err := EncryptAES(secret, sharedKey, 0)
		if err != nil {
			return nil, err
		}

		return append(ephemeralPub, encrypted...), nil

	case *rsa.PublicKey:
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, key, sharedKey, nil)

	default:
		return nil, fmt.Errorf("%w, got: %T", ErrNotSupportedKey, pub)
	}
}

func DecryptSharedSecret(sharedKey []byte, prv crypto.PrivateKey) ([]byte, error) {
	switch key := prv.(type) {
	case *ecdsa.PrivateKey:
		size := key.PublicKey.Params().BitSize / 8
		x, y, encrypted := sharedKey[:size], sharedKey[size:size*2], sharedKey[size*2:]
		public := &ecdsa.PublicKey{
			Curve: key.Curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}

		private, err := key.ECDH()
		if err != nil {
			return nil, err
		}

		pub, err := public.ECDH()
		if err != nil {
			return nil, err
		}

		secret, err := private.ECDH(pub)
		if err != nil {
			return nil, err
		}

		return DecryptAES(secret, encrypted, 0)

	case ed25519.PrivateKey:
		pubBytes, encryptedAESKey := sharedKey[:ed25519.PublicKeySize], sharedKey[ed25519.PublicKeySize:]
		xPrv := ed25519PrivateKeyToCurve25519(key)
		xPub, err := ed25519PublicKeyToCurve25519(ed25519.PublicKey(pubBytes))
		if err != nil {
			return nil, err
		}

		secret, err := curve25519.X25519(xPrv, xPub)
		if err != nil {
			return nil, err
		}

		return DecryptAES(secret, encryptedAESKey, 0)

	case *rsa.PrivateKey:
		return rsa.DecryptOAEP(sha256.New(), rand.Reader, key, sharedKey, nil)

	default:
		return nil, fmt.Errorf("%w, got: %T", ErrNotSupportedKey, prv)
	}
}
