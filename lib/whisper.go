package whisper

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ysmood/whisper/lib/piper"
	"github.com/ysmood/whisper/lib/secure"
)

const (
	APIVersion    = "v0.3.2"
	FormatVersion = byte(2)
)

type PrivateKey struct {
	Data []byte

	// Passphrase is used to decrypt the [PrivateKey.Data]
	Passphrase string
}

type PublicKey struct {
	Data []byte

	// A public ID for the public key, it can be a https url or github id.
	ID string

	// Uses to select the specific key in the URL file.
	// The line contains the Selector substring will be selected.
	Selector string
}

var ErrPubKeyNotFound = errors.New("public key not found")

func PublicKeyFromMeta(m string) PublicKey {
	i := strings.LastIndex(m, ":")

	if i == -1 {
		return PublicKey{ID: m}
	}

	return PublicKey{
		ID:       m[:i],
		Selector: m[i+1:],
	}
}

// Select the line in Data contains the Selector.
func (k PublicKey) Select() ([]byte, error) {
	for _, l := range splitIntoLines(k.Data) {
		if strings.Contains(l, k.Selector) {
			return []byte(l), nil
		}
	}

	return nil, fmt.Errorf("%w: %v", ErrPubKeyNotFound, k.Meta())
}

func (k PublicKey) Meta() string {
	return fmt.Sprintf("%s:%s", k.ID, k.Selector)
}

type Config struct {
	// Gzip compression level
	GzipLevel int

	// For data decryption and signature signing.
	Private *PrivateKey

	// For signature checking and meta data prefixing.
	Sign *PublicKey

	// For data encryption of different recipients
	Public []PublicKey
}

type Whisper struct {
	conf Config
}

// New encoder and decoder pair.
// The encoding process:
//
//	data -> sign -> gzip -> cipher -> meta
//
// The sign, gzip and base64 are optional.
//
// Decoding is the reverse as the encoding.
// It will still decode the whole data even the signature check fails, it will return [secure.ErrSignNotMatch] error.
func New(conf Config) piper.EncodeDecoder {
	return &Whisper{conf}
}

var ErrNoPrivateKey = errors.New("no private key")

var ErrPubPrvNotMatch = errors.New("public and private key not match")

func (w *Whisper) Encoder(out io.Writer) (io.WriteCloser, error) { //nolint: cyclop
	pipeline := []piper.EncodeDecoder{}

	// sign
	if w.conf.Sign != nil {
		if w.conf.Private == nil {
			return nil, ErrNoPrivateKey
		}

		belongs, err := secure.Belongs(w.conf.Sign.Data, w.conf.Private.Data, w.conf.Private.Passphrase)
		if err != nil {
			return nil, err
		}

		if !belongs {
			return nil, ErrPubPrvNotMatch
		}

		sign, err := secure.NewSignerBytes(w.conf.Private.Data, w.conf.Private.Passphrase)
		if err != nil {
			return nil, err
		}

		pipeline = append(pipeline, sign)
	}

	// gzip
	if w.conf.GzipLevel != gzip.NoCompression {
		pipeline = append(pipeline, &piper.Gzip{Level: w.conf.GzipLevel})
	}

	// cipher
	{
		publicKeys, err := selectPublicKeys(w.conf.Public)
		if err != nil {
			return nil, err
		}

		var prv PrivateKey
		if w.conf.Private != nil {
			prv = *w.conf.Private
		}

		cipher, err := secure.NewCipherBytes(prv.Data, prv.Passphrase, 0, publicKeys...)
		if err != nil {
			return nil, err
		}

		pipeline = append(pipeline, cipher)
	}

	// meta
	err := w.conf.EncodeMeta(out)
	if err != nil {
		return nil, err
	}

	return piper.Join(pipeline...).Encoder(out)
}

func (w *Whisper) Decoder(in io.Reader) (io.ReadCloser, error) {
	pipeline := []piper.EncodeDecoder{}

	// meta
	meta, err := DecodeMeta(in)
	if err != nil {
		return nil, err
	}

	// sign
	if meta.Sign {
		keys := [][]byte{}
		if w.conf.Sign != nil {
			key, err := w.conf.Sign.Select()
			if err != nil {
				return nil, err
			}
			keys = append(keys, key)
		}

		sign, err := secure.NewSignerBytes(nil, "", keys...)
		if err != nil {
			return nil, err
		}

		pipeline = append(pipeline, sign)
	}

	// gzip
	if meta.Gzip {
		pipeline = append(pipeline, &piper.Gzip{})
	}

	// cipher
	{
		if w.conf.Private == nil {
			return nil, ErrNoPrivateKey
		}

		index, err := meta.GetIndex(*w.conf.Private)
		if err != nil {
			return nil, err
		}

		cipher, err := secure.NewCipherBytes(w.conf.Private.Data, w.conf.Private.Passphrase, index)
		if err != nil {
			return nil, err
		}

		pipeline = append(pipeline, cipher)
	}

	return piper.Join(pipeline...).Decoder(in)
}

func EncodeString(data string, conf Config) (string, error) {
	bin, err := Encode([]byte(data), conf)
	return string(bin), err
}

func DecodeString(data string, conf Config) (string, error) {
	bin, err := Decode([]byte(data), conf)
	return string(bin), err
}

func Encode(data []byte, conf Config) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	wp := New(conf)

	w, err := wp.Encoder(buf)
	if err != nil {
		return nil, err
	}

	_, err = w.Write(data)
	if err != nil {
		return nil, err
	}

	err = w.Close()

	return buf.Bytes(), err
}

func Decode(data []byte, conf Config) ([]byte, error) {
	wp := New(conf)

	r, err := wp.Decoder(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	bin, err := io.ReadAll(r)
	if err != nil {
		return bin, err
	}

	err = r.Close()

	return bin, err
}
