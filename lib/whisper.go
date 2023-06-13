package whisper

import (
	"bytes"
	"compress/gzip"
	"io"

	"github.com/ysmood/whisper/lib/piper"
	"github.com/ysmood/whisper/lib/secure"
)

func New(publicKey, privateKey, privateKeyPassphrase string, gzipLevel int, base64 bool) (piper.EncodeDecoder, error) {
	list := []piper.EncodeDecoder{}

	publicBin, err := Base64Encoding.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}

	privateBin, err := Base64Encoding.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}

	ecc, err := secure.NewECC(publicBin, privateBin, privateKeyPassphrase)
	if err != nil {
		return nil, err
	}

	list = append(list, ecc, &piper.Gzip{Level: gzipLevel})

	if base64 {
		list = append(list, &piper.Base64{Encoding: Base64Encoding})
	}

	return piper.Join(list...), nil
}

func EncryptString(publicKey string, data string) (string, error) {
	bin, err := EncryptBytes(publicKey, []byte(data))
	return string(bin), err
}

func DecryptString(privateKey, privateKeyPassphrase string, data string) (string, error) {
	bin, err := DecryptBytes(privateKey, privateKeyPassphrase, []byte(data))
	return string(bin), err
}

func EncryptBytes(publicKey string, data []byte) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	wp, err := New(publicKey, "", "", gzip.DefaultCompression, true)
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

func DecryptBytes(privateKey, privateKeyPassphrase string, data []byte) ([]byte, error) {
	wp, err := New("", privateKey, privateKeyPassphrase, gzip.DefaultCompression, true)
	if err != nil {
		return nil, err
	}

	r, err := wp.Decoder(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	bin, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	err = r.Close()

	return bin, err
}

func GenKeysBase64(passphrase string) (public string, private string, err error) {
	publicBin, privateBin, err := secure.GenKeys(passphrase)
	if err != nil {
		return
	}

	public = Base64Encoding.EncodeToString(publicBin)
	private = Base64Encoding.EncodeToString(privateBin)

	return
}
