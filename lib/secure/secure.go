// Package secure makes encrypted data can only be decrypted by selected recipients.
// It allows different types of public keys to secretly exchange data.
//
// Suppose we have a opponent X, X0 represents its private key, X1 represents its public key.
// We have a pool of key pairs S, they accessible by everyone, they are pregenerated key pairs
// with the combinations of commonly use key types and sizes, such as 1024bit rsa 1024, 2048bit rsa, 256bit ecdsa, etc.
// Now we have opponents X and Y, they may have different key types, such as X's is rsa, Y's is ecdsa,
// we want to encrypt data D with X and decrypt it with Y. X has access to Y1.
//
// Encryption steps:
//
//	Find M0 from S that has the same key type and size as Y1.
//	Use Y1 and M0 to generate the shared secret key K.
//	Use K to encrypt the D to encrypted data E.
//	Send E to Y.
//
// Decryption steps:
//
//	Find M1 from S that has the same key type and size as Y0.
//	Use Y0 and M1 to generate the shared secret key K.
//	Use K to decrypt E.
package secure

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/ysmood/byframe/v4"
	"github.com/ysmood/whisper/lib/piper"
)

type Secure struct {
	pub []crypto.PublicKey
	prv crypto.PrivateKey
}

func New(privateKey []byte, passphrase string, publicKeys ...KeyWithFilter) (*Secure, error) {
	if len(publicKeys) == 0 {
		return nil, ErrPubKeyNotFound
	}

	prv, err := SSHPrvKey(privateKey, passphrase)
	if err != nil {
		return nil, err
	}

	pub := []crypto.PublicKey{}
	for _, publicKey := range publicKeys {
		b, err := publicKey.GetKey()
		if err != nil {
			return nil, err
		}

		key, err := SSHPubKey(b)
		if err != nil {
			return nil, err
		}

		pub = append(pub, key)
	}

	return &Secure{
		pub: pub,
		prv: prv,
	}, nil
}

// AESKeys returns the AES key and encrypted keys for each public key.
func (s *Secure) AESKeys() ([]byte, [][]byte, error) {
	aesKey := make([]byte, aes.BlockSize)
	_, err := rand.Read(aesKey)
	if err != nil {
		return nil, nil, err
	}

	encryptedKeys := [][]byte{}
	for _, pub := range s.pub {
		encryptedKey, err := EncryptSharedSecret(aesKey, pub)
		if err != nil {
			return nil, nil, err
		}

		encryptedKey = append(encryptedKey, PublicKeyID(pub)...)

		encryptedKeys = append(encryptedKeys, encryptedKey)
	}

	return aesKey, encryptedKeys, nil
}

func (s *Secure) Sign(data []byte) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	w, err := s.Signer().Encoder(buf)
	if err != nil {
		return nil, err
	}

	_, err = w.Write(data)
	if err != nil {
		return nil, err
	}

	err = w.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (s *Secure) Verify(data []byte) ([]byte, bool) {
	r, err := s.Signer().Decoder(bytes.NewBuffer(data))
	if err != nil {
		return nil, false
	}

	b, err := io.ReadAll(r)
	if err != nil {
		return nil, false
	}

	return b, true
}

func (s *Secure) SigDigest(digest []byte) ([]byte, error) {
	switch key := s.prv.(type) {
	case *ecdsa.PrivateKey:
		return key.Sign(rand.Reader, digest, nil)
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	case ed25519.PrivateKey:
		return ed25519.Sign(key, digest), nil
	default:
		return nil, fmt.Errorf("%w, got: %T", ErrNotSupportedKey, s.prv)
	}
}

func (s *Secure) VerifyDigest(digest, sign []byte) bool {
	switch key := s.pub[0].(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(key, digest, sign)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, sign) == nil
	case ed25519.PublicKey:
		return ed25519.Verify(key, digest, sign)
	default:
		return false
	}
}

type Cipher struct {
	Key *Secure
}

func (k *Secure) Cipher() *Cipher {
	return &Cipher{Key: k}
}

// Encoder format is:
//
//	[encrypted key count][aes key 1][aes key 2]...[encrypted data].
//
// Each key is for a public key.
func (c *Cipher) Encoder(w io.Writer) (io.WriteCloser, error) {
	aesKey, encryptedKeys, err := c.Key.AESKeys()
	if err != nil {
		return nil, err
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

	return piper.NewAES(aesKey, 2).Encoder(w)
}

func (c *Cipher) Decoder(r io.Reader) (io.ReadCloser, error) {
	s := byframe.NewScanner(r)

	header, err := s.Next()
	if err != nil {
		return nil, err
	}

	_, count := byframe.DecodeHeader(header)

	encryptedKeys := [][]byte{}
	for i := 0; i < count; i++ {
		encryptedKey, err := s.Next()
		if err != nil {
			return nil, err
		}
		encryptedKeys = append(encryptedKeys, encryptedKey)
	}

	aesKey, err := c.DecodeAESKey(encryptedKeys)
	if err != nil {
		return nil, err
	}

	return piper.NewAES(aesKey, 2).Decoder(r)
}

func (c *Cipher) DecodeAESKey(encryptedKeys [][]byte) ([]byte, error) {
	var encryptedKey []byte
	id := PublicKeyIDByPrivateKey(c.Key.prv)

	for _, encryptedKey = range encryptedKeys {
		if bytes.Equal(encryptedKey[:PUBLIC_KEY_ID_SIZE], id) {
			return DecryptSharedSecret(encryptedKey[PUBLIC_KEY_ID_SIZE:], c.Key.prv)
		}
	}

	return nil, fmt.Errorf("the private key is not a recipient :%w", ErrPrvKeyNotFound)
}
