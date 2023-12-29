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

type PrivateKey struct {
	Data []byte

	// Passphrase is used to decrypt the [PrivateKey.Data]
	Passphrase string

	Sign bool
}

type PublicKey struct {
	Data []byte

	Filter string

	// Such as github id @ysmood, or https url @https://github/ysmood.keys
	FileLink string
}

var ErrPubKeyNotFound = errors.New("public key not found")

func (k PublicKey) GetKey() ([]byte, error) {
	for _, l := range splitIntoLines(k.Data) {
		if strings.Contains(l, k.Filter) {
			return []byte(l), nil
		}
	}

	return nil, fmt.Errorf("%w with filter: %s", ErrPubKeyNotFound, k.Filter)
}

type Config struct {
	GzipLevel int
	Base64    bool
	Private   PrivateKey
	Public    []PublicKey
}

// New data encoding flow:
//
//	data -> gzip -> encrypt -> base64
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

func EncodeString(data string, sender PrivateKey, recipients ...[]byte) (string, error) {
	bin, err := Encode([]byte(data), sender, recipients...)
	return string(bin), err
}

func DecodeString(data string, recipient PrivateKey, sender []byte) (string, error) {
	bin, err := Decode([]byte(data), recipient, sender)
	return string(bin), err
}

func Encode(data []byte, sender PrivateKey, recipients ...[]byte) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	wp, err := New(Config{gzip.DefaultCompression, true, sender, toPublicKey(recipients)})
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

func Decode(data []byte, recipient PrivateKey, sender []byte) ([]byte, error) {
	wp, err := New(Config{0, true, recipient, toPublicKey([][]byte{sender})})
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
