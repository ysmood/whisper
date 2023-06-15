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
func New(pub PublicKey, prv PrivateKey, gzipLevel int, base64 bool) (piper.EncodeDecoder, error) {
	key, err := ParseKeysInBase64(pub, prv)
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

func ParseKeysInBase64(pub PublicKey, prv PrivateKey) (*secure.Key, error) {
	publicBin, err := Base64Encoding.DecodeString(string(pub))
	if err != nil {
		return nil, err
	}

	privateBin, err := Base64Encoding.DecodeString(prv.Data)
	if err != nil {
		return nil, err
	}

	return secure.New(publicBin, privateBin, prv.Passphrase)
}

func EncodeString(sender PrivateKey, receiver PublicKey, data string) (string, error) {
	bin, err := Encode(sender, receiver, []byte(data))
	return string(bin), err
}

func DecodeString(receiver PrivateKey, sender PublicKey, data string) (string, error) {
	bin, err := Decode(receiver, sender, []byte(data))
	return string(bin), err
}

func Encode(sender PrivateKey, receiver PublicKey, data []byte) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	wp, err := New(receiver, sender, gzip.DefaultCompression, true)
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

func Decode(receiver PrivateKey, sender PublicKey, data []byte) ([]byte, error) {
	wp, err := New(sender, receiver, 0, true)
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

func GenKeysInBase64(passphrase string) (PublicKey, PrivateKey, error) {
	publicBin, privateBin, err := secure.GenKeys(passphrase)
	if err != nil {
		return "", PrivateKey{}, err
	}

	return PublicKey(Base64Encoding.EncodeToString(publicBin)),
		PrivateKey{
			Data:       Base64Encoding.EncodeToString(privateBin),
			Passphrase: passphrase,
		}, nil
}
