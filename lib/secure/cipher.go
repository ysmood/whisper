package secure

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ysmood/byframe/v4"
	"github.com/ysmood/whisper/lib/piper"
)

// Cipher to encrypt and decrypt data.
// The cipher will generate a random AES secret, each public key will be used to encrypt the AES secret into a key.
// The wire format looks like this:
//
//	[n][key1][key2][key3]...[encrypted-data].
//
// [n] is the number of keys.
// [key1] is the encrypted key for the first public key.
// [key2] is the encrypted key for the second public key.
// ...
// [encrypted-data] is the encrypted data by the AES secret.
type Cipher struct {
	Secure *Secure
}

func (s *Secure) Cipher() *Cipher {
	return &Cipher{Secure: s}
}

func (c *Cipher) Encoder(w io.Writer) (io.WriteCloser, error) {
	aesKey, encryptedKeys, err := c.Secure.AESKeys()
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

var ErrNotRecipient = fmt.Errorf("not a recipient")

func (c *Cipher) DecodeAESKey(encryptedKeys [][]byte) ([]byte, error) {
	var encryptedKey []byte
	id := PublicKeyIDByPrivateKey(c.Secure.prv)

	for _, encryptedKey = range encryptedKeys {
		if bytes.Equal(encryptedKey[:PUBLIC_KEY_ID_SIZE], id) {
			return DecryptSharedSecret(encryptedKey[PUBLIC_KEY_ID_SIZE:], c.Secure.prv)
		}
	}

	return nil, ErrNotRecipient
}
