package piper

import (
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"io"
)

type Base64 struct {
	Encoding *base64.Encoding
}

func NewBase64() EncodeDecoder {
	return &Base64{Encoding: base64.StdEncoding}
}

func (e *Base64) Encoder(w io.Writer) (io.WriteCloser, error) {
	return base64.NewEncoder(e.Encoding, w), nil
}

func (e *Base64) Decoder(r io.Reader) (io.ReadCloser, error) {
	return io.NopCloser(base64.NewDecoder(e.Encoding, r)), nil
}

type Gzip struct {
	Level int
}

func NewGzip() EncodeDecoder {
	return &Gzip{Level: gzip.DefaultCompression}
}

func (g *Gzip) Encoder(w io.Writer) (io.WriteCloser, error) {
	return gzip.NewWriterLevel(w, g.Level)
}

func (g *Gzip) Decoder(r io.Reader) (io.ReadCloser, error) {
	return gzip.NewReader(r)
}

type AES struct {
	Key []byte
}

func NewAES(key []byte) EncodeDecoder {
	return &AES{Key: key}
}

func (a *AES) Encoder(w io.Writer) (io.WriteCloser, error) {
	hashedKey := md5.Sum(a.Key)
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}

	_, err = w.Write(iv)
	if err != nil {
		return nil, err
	}

	return &cipher.StreamWriter{
		S: cipher.NewOFB(block, iv),
		W: w,
	}, nil
}

func (a *AES) Decoder(r io.Reader) (io.ReadCloser, error) {
	hashedKey := md5.Sum(a.Key)
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(r, iv)
	if err != nil {
		return nil, err
	}

	return io.NopCloser(&cipher.StreamReader{
		S: cipher.NewOFB(block, iv),
		R: r,
	}), nil
}
