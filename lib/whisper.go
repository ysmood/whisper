package whisper

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ysmood/whisper/lib/piper"
	"github.com/ysmood/whisper/lib/secure"
)

const (
	APIVersion        = "v0.9.0"
	WireFormatVersion = byte(8)
)

type PrivateKey struct {
	Data []byte

	// Passphrase is used to decrypt the [PrivateKey.Data]
	Passphrase string
}

type PublicKey struct {
	Data []byte

	Meta PublicKeyMeta
}

type PublicKeyMeta struct {
	// A public ID for the public key, it can be a https url or github id.
	ID string

	// Uses to select the specific key in the URL file.
	// The line contains the Selector substring will be selected.
	Selector string
}

func NewPublicKeyMeta(m string) PublicKeyMeta {
	i := strings.LastIndex(strings.TrimPrefix(m, "https://"), ":")

	if i == -1 {
		return PublicKeyMeta{ID: m}
	}

	return PublicKeyMeta{
		ID:       m[:i],
		Selector: m[i+1:],
	}
}

func (k PublicKeyMeta) String() string {
	list := []string{k.ID}
	if k.Selector != "" {
		list = append(list, k.Selector)
	}
	return strings.Join(list, ":")
}

var ErrPubKeyNotFound = errors.New("public key not found")

// Select the line in Data contains the Selector.
func (k PublicKey) Select() ([]byte, error) {
	for _, l := range splitIntoLines(k.Data) {
		if strings.Contains(l, k.Meta.Selector) {
			return []byte(l), nil
		}
	}

	return nil, fmt.Errorf("%w: \"%v\"", ErrPubKeyNotFound, k.Meta.String())
}

type Config struct {
	// Gzip compression level
	GzipLevel int

	// For data decryption and signature signing.
	Private *PrivateKey

	// For signature checking and meta data prefixing.
	Sign *PublicKey

	// For data encryption of different recipients.
	// If the list is empty, it will be a decryption process.
	Public []PublicKey
}

func (c Config) IsDecryption() bool {
	return len(c.Public) == 0
}

// Whisper is a data encryption and decryption file format.
// The whisper file extension is ".wsp".
type Whisper struct {
	conf Config
}

// New encoder and decoder pair.
// The encoding process:
//
//	data -> gzip -> cipher -> sign -> meta
//
// The sign, gzip are optional.
//
// Decoding is the reverse as the encoding.
// It will still decode the whole data even the signature check fails, it will return [secure.ErrSignNotMatch] error.
func New(conf Config) *Whisper {
	return &Whisper{conf}
}

var ErrNoPrivateKey = errors.New("no private key")

var ErrPubPrvNotMatch = errors.New("public and private key not match")

// Encoder encrypt data stream to the out as whisper file format.
func (w *Whisper) Encoder(out io.Writer) (io.WriteCloser, error) {
	pipeline := []piper.EncodeDecoder{}

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

	// meta
	err := w.conf.EncodeMeta(out)
	if err != nil {
		return nil, err
	}

	return piper.Join(pipeline...).Encoder(out)
}

// Decoder decrypt data stream from the in as whisper file format.
func (w *Whisper) Decoder(in io.Reader) (io.ReadCloser, error) {
	pipeline := []piper.EncodeDecoder{}

	meta, err := DecodeMeta(in)
	if err != nil {
		return nil, err
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

	return piper.Join(pipeline...).Decoder(in)
}
