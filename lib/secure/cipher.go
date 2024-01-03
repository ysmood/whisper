// Package secure makes encrypted data can only be decrypted by selected recipients.
// It allows different types of public keys to secretly exchange data.
//
// Suppose we have a opponent X, append 0 to the upper cased letter we get X0, it represents X's private key,
// similarly X1 represents X's public key.
// We have a pool of key pairs S, they are accessible by everyone, they are pregenerated key pairs
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
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/ysmood/byframe/v4"
	"github.com/ysmood/whisper/lib/piper"
)

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
	aesKey := make([]byte, aes.BlockSize)
	_, err := rand.Read(aesKey)
	if err != nil {
		return nil, err
	}

	encryptedKeys := [][]byte{}
	for _, pub := range c.pubs {
		encrypted, err := c.EncodeAESKey(aesKey, pub)
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

	return piper.NewAES(aesKey, c.AESType, 2).Encoder(w)
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
		encrypted, err := s.Next()
		if err != nil {
			return nil, err
		}
		encryptedKeys = append(encryptedKeys, encrypted)
	}

	aesKey, err := c.DecodeAESKey(encryptedKeys)
	if err != nil {
		return nil, err
	}

	return piper.NewAES(aesKey, c.AESType, 2).Decoder(r)
}

var ErrNotRecipient = fmt.Errorf("not a recipient")

func (c *Cipher) EncodeAESKey(aesKey []byte, pub crypto.PublicKey) ([]byte, error) {
	encryptedKey, err := EncryptSharedSecret(aesKey, c.AESType, pub)
	if err != nil {
		return nil, err
	}

	return encryptedKey, nil
}

func (c *Cipher) DecodeAESKey(encryptedKeys [][]byte) ([]byte, error) {
	return DecryptSharedSecret(encryptedKeys[c.index], c.AESType, c.prv)
}
