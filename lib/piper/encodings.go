package piper

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

type Transparent struct{}

func (t *Transparent) Encoder(w io.Writer) (io.WriteCloser, error) {
	if wc, ok := w.(io.WriteCloser); ok {
		return wc, nil
	}

	return NopCloser(w), nil
}

func (t *Transparent) Decoder(r io.Reader) (io.ReadCloser, error) {
	if rc, ok := r.(io.ReadCloser); ok {
		return rc, nil
	}

	return io.NopCloser(r), nil
}

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
	Key   []byte
	Guard int
}

func NewAES(key []byte, guard int) EncodeDecoder {
	if guard > aes.BlockSize {
		panic("guard size can't be larger than aes.BlockSize")
	}

	return &AES{Key: key, Guard: guard}
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

	s := &cipher.StreamWriter{
		S: cipher.NewOFB(block, iv),
		W: w,
	}

	// https://www.rfc-editor.org/rfc/rfc4880#section-5.13
	_, err = s.Write(iv[:a.Guard])
	if err != nil {
		return nil, err
	}

	return s, nil
}

var ErrAESDecode = errors.New("wrong secret or corrupted data")

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

	rc := io.NopCloser(&cipher.StreamReader{
		S: cipher.NewOFB(block, iv),
		R: r,
	})

	guard := make([]byte, a.Guard)

	_, err = io.ReadFull(rc, guard)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(guard, iv[:a.Guard]) {
		return nil, ErrAESDecode
	}

	return rc, nil
}
