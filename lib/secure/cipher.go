package secure

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ysmood/byframe/v4"
	"github.com/ysmood/whisper/lib/piper"
)

type Cipher struct {
	Secure *Secure
}

func (s *Secure) Cipher() *Cipher {
	return &Cipher{Secure: s}
}

// Encoder format is:
//
//	[encrypted key count][aes key 1][aes key 2]...[encrypted data].
//
// Each key is for a public key.
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

func (c *Cipher) DecodeAESKey(encryptedKeys [][]byte) ([]byte, error) {
	var encryptedKey []byte
	id := PublicKeyIDByPrivateKey(c.Secure.prv)

	for _, encryptedKey = range encryptedKeys {
		if bytes.Equal(encryptedKey[:PUBLIC_KEY_ID_SIZE], id) {
			return DecryptSharedSecret(encryptedKey[PUBLIC_KEY_ID_SIZE:], c.Secure.prv)
		}
	}

	return nil, fmt.Errorf("the private key is not a recipient: %w", ErrPrvKeyNotFound)
}
