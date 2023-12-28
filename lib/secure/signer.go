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

	"github.com/ysmood/byframe/v4"
	"github.com/ysmood/whisper/lib/piper"
)

type Signer struct {
	prv crypto.PrivateKey
	pub crypto.PublicKey
}

func NewSigner(prv crypto.PrivateKey, pub crypto.PrivateKey) *Signer {
	return &Signer{prv, pub}
}

func (s *Signer) Sign(data []byte) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	w, err := s.Encoder(buf)
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

func (s *Signer) Verify(data []byte) ([]byte, bool) {
	r, err := s.Decoder(bytes.NewBuffer(data))
	if err != nil {
		return nil, false
	}

	b, err := io.ReadAll(r)
	if err != nil {
		return b, false
	}

	return b, true
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

			sign, err := s.SigDigest(h.Sum(nil))
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
			} else if !s.VerifyDigest(h.Sum(nil), sign) {
				return 0, ErrSignNotMatch
			}

			return n, nil
		},
		C: func() error {
			return piper.Close(r)
		},
	}, nil
}

func (s *Signer) SigDigest(digest []byte) ([]byte, error) {
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

func (s *Signer) VerifyDigest(digest, sign []byte) bool {
	if s.pub == nil {
		return false
	}

	switch key := s.pub.(type) {
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
