package secure

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/ysmood/byframe/v4"
	"github.com/ysmood/whisper/lib/piper"
)

type Key struct {
	pub []crypto.PublicKey
	prv crypto.PrivateKey
}

func New(privateKey []byte, passphrase string, publicKeys ...KeyWithFilter) (*Key, error) {
	if len(publicKeys) == 0 {
		return nil, ErrPubKeyNotFound
	}

	prv, err := SSHPrvKey(privateKey, passphrase)
	if err != nil {
		return nil, err
	}

	typePrefix := PrivateKeyTypePrefix(prv)

	pub := []crypto.PublicKey{}
	for _, publicKey := range publicKeys {
		b, err := publicKey.GetKey(typePrefix)
		if err != nil {
			return nil, err
		}

		key, err := SSHPubKey(b)
		if err != nil {
			return nil, err
		}

		pub = append(pub, key)
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
	if k.IsRSA() {
		return k.rsaAESKeys()
	}

	if len(k.pub) == 1 {
		key, err := SharedSecret(k.prv, k.pub[0])
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
		key, err := SharedSecret(k.prv, pub)
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

func (k *Key) rsaAESKeys() ([]byte, [][]byte, error) {
	encryptedKeys := [][]byte{}

	secretKey := make([]byte, 32)
	_, err := rand.Read(secretKey)
	if err != nil {
		return nil, nil, err
	}

	for _, pub := range k.pub {
		pubKey := pub.(*rsa.PublicKey)
		encryptedKey, err := rsaEncrypt(pubKey, secretKey)
		if err != nil {
			return nil, nil, err
		}

		signed, err := k.Sign(encryptedKey)
		if err != nil {
			return nil, nil, err
		}

		encryptedKeys = append(encryptedKeys, signed)
	}

	return secretKey, encryptedKeys, nil
}

func (k *Key) Sign(data []byte) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	w, err := k.Signer().Encoder(buf)
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

func (k *Key) Verify(data []byte) ([]byte, bool) {
	r, err := k.Signer().Decoder(bytes.NewBuffer(data))
	if err != nil {
		return nil, false
	}

	b, err := io.ReadAll(r)
	if err != nil {
		return nil, false
	}

	return b, true
}

func (k *Key) SigDigest(digest []byte) ([]byte, error) {
	switch key := k.prv.(type) {
	case *ecdsa.PrivateKey:
		return key.Sign(rand.Reader, digest, nil)
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	default:
		return nil, fmt.Errorf("%w, got: %T", ErrNotSupportedKey, k.prv)
	}
}

func (k *Key) VerifyDigest(digest, sign []byte) bool {
	switch key := k.pub[0].(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(key, digest, sign)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, sign) == nil
	default:
		return false
	}
}

func (k *Key) IsRSA() bool {
	_, ok := k.prv.(*rsa.PrivateKey)
	return ok
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

	aesKey, err := c.DecodeAESKey(encryptedKeys)
	if err != nil {
		return nil, err
	}

	return piper.NewAES(aesKey).Decoder(r)
}

func (c *Cipher) DecodeAESKey(encryptedKeys [][]byte) ([]byte, error) {
	var aesKey []byte

	if c.Key.IsRSA() {
		for _, signed := range encryptedKeys {
			encryptedKey, valid := c.Key.Verify(signed)
			if !valid {
				continue
			}

			var err error
			aesKey, err = rsaDecrypt(c.Key.prv.(*rsa.PrivateKey), encryptedKey)
			if err != nil {
				return nil, err
			}
		}

		return aesKey, nil
	}

	key, err := SharedSecret(c.Key.prv, c.Key.pub[0])
	if err != nil {
		return nil, err
	}

	if len(encryptedKeys) == 0 {
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

	return aesKey, nil
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

			sign, err := s.Key.SigDigest(h.Sum(nil))
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
			} else if !s.Key.VerifyDigest(h.Sum(nil), sign) {
				return 0, ErrSignNotMatch
			}

			return n, nil
		},
		C: func() error {
			return piper.Close(r)
		},
	}, nil
}

func SharedSecret(prv crypto.PrivateKey, pub crypto.PublicKey) ([]byte, error) {
	switch key := prv.(type) {
	case *ecdsa.PrivateKey:
		private, err := key.ECDH()
		if err != nil {
			return nil, err
		}

		public, err := pub.(*ecdsa.PublicKey).ECDH()
		if err != nil {
			return nil, err
		}

		return private.ECDH(public)

	default:
		return nil, fmt.Errorf("%w, got: %T", ErrNotSupportedKey, prv)
	}
}

func rsaEncrypt(pub *rsa.PublicKey, data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)
}

func rsaDecrypt(prv *rsa.PrivateKey, data []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, prv, data, nil)
}
