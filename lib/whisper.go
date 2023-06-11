package whisper

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"

	"github.com/ysmood/whisper/lib/secure"
)

func GenKeysBase64(passphrase string) (private string, public string, err error) {
	privateBin, publicBin, err := secure.GenKeys(passphrase)
	if err != nil {
		return
	}

	private = Base64Encoding.EncodeToString(privateBin)
	public = Base64Encoding.EncodeToString(publicBin)

	return
}

func EncryptString(publicKey string, data string, gzipLevel int) (string, error) {
	bin, err := EncryptBytes(publicKey, []byte(data), gzipLevel)
	return string(bin), err
}

func DecryptString(privateKey, privateKeyPassphrase string, data string) (string, error) {
	bin, err := DecryptBytes(privateKey, privateKeyPassphrase, []byte(data))
	return string(bin), err
}

func EncryptBytes(publicKey string, data []byte, gzipLevel int) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	enc, err := Encrypt(publicKey, buf, gzipLevel)
	if err != nil {
		return nil, err
	}

	_, err = enc.Write(data)
	if err != nil {
		return nil, err
	}

	err = enc.Close()

	return buf.Bytes(), err
}

func DecryptBytes(privateKey, privateKeyPassphrase string, data []byte) ([]byte, error) {
	dec, err := Decrypt(privateKey, privateKeyPassphrase, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	bin, err := io.ReadAll(dec)
	if err != nil {
		return nil, err
	}

	err = dec.Close()

	return bin, err
}

// Encrypt data with public key. The data flow is:
//
//	data -> gip -> encrypt -> base64
func Encrypt(publicKey string, data io.Writer, gzipLevel int) (io.WriteCloser, error) {
	encBase64 := base64.NewEncoder(Base64Encoding, data)

	keyBin, err := Base64Encoding.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}

	key, err := secure.LoadPublicKey(keyBin)
	if err != nil {
		return nil, err
	}

	encrypted, err := secure.Encrypt(key, encBase64)
	if err != nil {
		return nil, err
	}

	encGzip, err := gzip.NewWriterLevel(encrypted, gzipLevel)
	if err != nil {
		return nil, err
	}

	return NewCloseWriters(encGzip, encGzip, encBase64), nil
}

func Decrypt(privateKey, privateKeyPassphrase string, data io.Reader) (io.ReadCloser, error) {
	decBase64 := base64.NewDecoder(Base64Encoding, data)

	keyBin, err := Base64Encoding.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}

	key, err := secure.LoadPrivateKey(privateKeyPassphrase, keyBin)
	if err != nil {
		return nil, err
	}

	decrypted, err := secure.Decrypt(key, decBase64)
	if err != nil {
		return nil, err
	}

	decGzip, err := gzip.NewReader(decrypted)
	if err != nil {
		return nil, err
	}

	return NewCloseReaders(decGzip, decGzip), nil
}
