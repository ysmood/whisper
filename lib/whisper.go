package whisper

import (
	"bytes"
	"compress/gzip"
	"io"

	"github.com/ysmood/whisper/lib/piper"
	"github.com/ysmood/whisper/lib/secure"
)

type Config struct {
	GzipLevel int
	Base64    bool
	Private   PrivateKey
	Public    [][]byte
}

// New data encoding flow:
//
//	data -> gzip -> encrypt -> base64
//
// Only gzip is required, others are optional.
func New(conf Config) (piper.EncodeDecoder, error) {
	key, err := secure.New(conf.Private.Data, conf.Private.Passphrase, conf.Public...)
	if err != nil {
		return nil, err
	}

	list := []piper.EncodeDecoder{&piper.Gzip{Level: conf.GzipLevel}, key.Cipher()}

	if conf.Base64 {
		list = append(list, &piper.Base64{Encoding: Base64Encoding})
	}

	return piper.Join(list...), nil
}

type PrivateKey struct {
	Data []byte

	// Passphrase is used to decrypt the [PrivateKey.Data]
	Passphrase string
}

func EncodeString(data string, sender PrivateKey, receivers ...[]byte) (string, error) {
	bin, err := Encode([]byte(data), sender, receivers...)
	return string(bin), err
}

func DecodeString(data string, receiver PrivateKey, sender []byte) (string, error) {
	bin, err := Decode([]byte(data), receiver, sender)
	return string(bin), err
}

func Encode(data []byte, sender PrivateKey, receivers ...[]byte) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	wp, err := New(Config{gzip.DefaultCompression, true, sender, receivers})
	if err != nil {
		return nil, err
	}

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

func Decode(data []byte, receiver PrivateKey, sender []byte) ([]byte, error) {
	wp, err := New(Config{0, true, receiver, [][]byte{sender}})
	if err != nil {
		return nil, err
	}

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
