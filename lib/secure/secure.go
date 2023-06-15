package secure

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"

	"github.com/ysmood/byframe/v3"
	"github.com/ysmood/whisper/lib/piper"
)

type Key struct {
	pub *ecdsa.PublicKey
	prv *ecdsa.PrivateKey
}

// New key. Either or both of publicKey or privateKey must be provided.
func New(publicKey, privateKey []byte, passphrase string) (*Key, error) {
	var err error
	var pub interface{}

	if len(publicKey) > 0 {
		pub, err = x509.ParsePKIXPublicKey(publicKey)
		if err != nil {
			return nil, err
		}
	} else {
		pub = (*ecdsa.PublicKey)(nil)
	}

	var prv interface{}
	if len(privateKey) > 0 {
		keyData, err := DecryptAES(passphrase, privateKey)
		if err != nil {
			return nil, err
		}

		prv, err = x509.ParsePKCS8PrivateKey(keyData)
		if err != nil {
			return nil, err
		}
	} else {
		prv = (*ecdsa.PrivateKey)(nil)
	}

	return &Key{
		pub: pub.(*ecdsa.PublicKey),
		prv: prv.(*ecdsa.PrivateKey),
	}, nil
}

func (k *Key) AESKey() ([]byte, error) {
	private, err := k.prv.ECDH()
	if err != nil {
		return nil, err
	}

	public, err := k.pub.ECDH()
	if err != nil {
		return nil, err
	}

	return private.ECDH(public)
}

func (k *Key) Sign(digest []byte) ([]byte, error) {
	return k.prv.Sign(rand.Reader, digest, nil)
}

func (k *Key) Verify(digest, sign []byte) bool {
	return ecdsa.VerifyASN1(k.pub, digest, sign)
}

type Cipher struct {
	Key *Key
}

func (k *Key) Cipher() *Cipher {
	return &Cipher{Key: k}
}

func (c *Cipher) Encoder(w io.Writer) (io.WriteCloser, error) {
	aesKey, err := c.Key.AESKey()
	if err != nil {
		return nil, err
	}

	return piper.NewAES(aesKey).Encoder(w)
}

func (c *Cipher) Decoder(r io.Reader) (io.ReadCloser, error) {
	aesKey, err := c.Key.AESKey()
	if err != nil {
		return nil, err
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
