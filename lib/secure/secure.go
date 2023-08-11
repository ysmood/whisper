package secure

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/ysmood/byframe/v4"
	"github.com/ysmood/whisper/lib/piper"
)

type Key struct {
	pub []*ecdsa.PublicKey
	prv *ecdsa.PrivateKey
}

func New(privateKey []byte, passphrase string, publicKeys ...[]byte) (*Key, error) {
	pub := []*ecdsa.PublicKey{}
	for _, publicKey := range publicKeys {
		key, err := SSHPubKey(publicKey)
		if err != nil {
			return nil, err
		}

		pub = append(pub, key)
	}

	prv, err := SSHKey(privateKey, passphrase)
	if err != nil {
		return nil, err
	}

	return &Key{
		pub: pub,
		prv: prv,
	}, nil
}

// AESKeys returns the AES key and encrypted keys for each public key.
// If there's only one public key, the AES key will be the ECDH key.
// If there're multiple public keys, a random base AES key will be generated,
// then each ECDH key will be used to encrypt the base AES key.
func (k *Key) AESKeys() ([]byte, [][]byte, error) {
	if len(k.pub) == 1 {
		key, err := ECDH(k.prv, k.pub[0])
		if err != nil {
			return nil, nil, err
		}
		return key, nil, nil
	}

	aesKey := make([]byte, aes.BlockSize)
	_, err := rand.Read(aesKey)
	if err != nil {
		return nil, nil, err
	}

	encryptedKeys := [][]byte{}
	for _, pub := range k.pub {
		key, err := ECDH(k.prv, pub)
		if err != nil {
			return nil, nil, err
		}

		encryptedKey, err := EncryptAES(key, aesKey)
		if err != nil {
			return nil, nil, err
		}

		encryptedKeys = append(encryptedKeys, encryptedKey)
	}

	return aesKey, encryptedKeys, nil
}

func (k *Key) Sign(digest []byte) ([]byte, error) {
	return k.prv.Sign(rand.Reader, digest, nil)
}

func (k *Key) Verify(digest, sign []byte) bool {
	return ecdsa.VerifyASN1(k.pub[0], digest, sign)
}

type Cipher struct {
	Key *Key
}

func (k *Key) Cipher() *Cipher {
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

	return piper.NewAES(aesKey).Encoder(w)
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

	key, err := ECDH(c.Key.prv, c.Key.pub[0])
	if err != nil {
		return nil, err
	}

	var aesKey []byte

	if count == 0 {
		aesKey = key
	} else {
		for _, encryptedKey := range encryptedKeys {
			aesKey, err = DecryptAES(key, encryptedKey)
			if err == nil {
				break
			} else if !errors.Is(err, piper.ErrAESDecode) {
				return nil, err
			}
		}
	}

	return piper.NewAES(aesKey).Decoder(r)
}

type Signer struct {
	Key *Key
}

func (k *Key) Signer() *Signer {
	return &Signer{Key: k}
}

func (s *Signer) Encoder(w io.Writer) (io.WriteCloser, error) {
	empty := []byte{}
	h := sha256.New()
	closed := false

	return piper.WriteClose{
		W: func(p []byte) (n int, err error) {
			n = len(p)

			_, err = h.Write(p)
			if err != nil {
				return 0, err
			}

			_, err = w.Write(append(byframe.Encode(p), byframe.Encode(empty)...))
			return
		},
		C: func() error {
			if closed {
				return nil
			}
			closed = true

			sign, err := s.Key.Sign(h.Sum(nil))
			if err != nil {
				return err
			}

			_, err = w.Write(append(byframe.Encode(empty), byframe.Encode(sign)...))
			if err != nil {
				return err
			}

			return piper.Close(w)
		},
	}, nil
}

var ErrSignNotMatch = errors.New("sign not match")

func (s *Signer) Decoder(r io.Reader) (io.ReadCloser, error) {
	f := byframe.NewScanner(r)
	f.Limit(1024 * 1024)
	buf := piper.Buffer{}
	h := sha256.New()

	return piper.ReadClose{
		R: func(p []byte) (n int, err error) {
			if len(buf) > 0 {
				n = buf.Consume(p)
				return n, nil
			}

			data, err := f.Next()
			if err != nil {
				return 0, err
			}

			_, err = h.Write(data)
			if err != nil {
				return 0, err
			}

			sign, err := f.Next()
			if err != nil {
				return 0, err
			}

			if len(sign) == 0 {
				buf = data
				n = buf.Consume(p)
			} else if !s.Key.Verify(h.Sum(nil), sign) {
				return 0, ErrSignNotMatch
			}

			return n, nil
		},
		C: func() error {
			return piper.Close(r)
		},
	}, nil
}

func ECDH(prv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	private, err := prv.ECDH()
	if err != nil {
		return nil, err
	}

	public, err := pub.ECDH()
	if err != nil {
		return nil, err
	}

	return private.ECDH(public)
}
