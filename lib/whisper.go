package whisper

import (
	"bytes"
	"compress/gzip"
	"io"

	"github.com/ysmood/whisper/lib/piper"
	"github.com/ysmood/whisper/lib/secure"
)

// New data encoding flow:
//
//	data -> gzip -> encrypt -> base64
//
// Only gzip is required, others are optional.
func New(gzipLevel int, base64 bool, prv PrivateKey, pub ...PublicKey) (piper.EncodeDecoder, error) {
	key, err := ParseKeysInBase64(prv, pub...)
	if err != nil {
		return nil, err
	}

	list := []piper.EncodeDecoder{&piper.Gzip{Level: gzipLevel}, key.Cipher()}

	if base64 {
		list = append(list, &piper.Base64{Encoding: Base64Encoding})
	}

	return piper.Join(list...), nil
}

type PrivateKey struct {
	Data string

	// Passphrase is used to decrypt the [PrivateKey.Data]
	Passphrase string
}

type PublicKey string

func ParseKeysInBase64(prv PrivateKey, pub ...PublicKey) (*secure.Key, error) {
	publicBins := [][]byte{}
	for _, p := range pub {
		publicBin, err := Base64Encoding.DecodeString(string(p))
		if err != nil {
			return nil, err
		}

		publicBins = append(publicBins, publicBin)
	}

	privateBin, err := Base64Encoding.DecodeString(prv.Data)
	if err != nil {
		return nil, err
	}

	return secure.New(privateBin, prv.Passphrase, publicBins...)
}

func EncodeString(data string, sender PrivateKey, receivers ...PublicKey) (string, error) {
	bin, err := Encode([]byte(data), sender, receivers...)
	return string(bin), err
}

func DecodeString(data string, receiver PrivateKey, sender PublicKey) (string, error) {
	bin, err := Decode([]byte(data), receiver, sender)
	return string(bin), err
}

func Encode(data []byte, sender PrivateKey, receivers ...PublicKey) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	wp, err := New(gzip.DefaultCompression, true, sender, receivers...)
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

func Decode(data []byte, receiver PrivateKey, sender PublicKey) ([]byte, error) {
	wp, err := New(0, true, receiver, sender)
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

func GenKeysInBase64(passphrase string) (PrivateKey, PublicKey, error) {
	privateBin, publicBin, err := secure.GenKeys(passphrase)
	if err != nil {
		return PrivateKey{}, "", err
	}

	return PrivateKey{
			Data:       Base64Encoding.EncodeToString(privateBin),
			Passphrase: passphrase,
		},
		PublicKey(Base64Encoding.EncodeToString(publicBin)),
		nil
}
