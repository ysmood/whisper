package piper

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

type Transparent struct{}

func (t *Transparent) Encoder(w io.Writer) (io.WriteCloser, error) {
	return NopCloser(w), nil
}

func (t *Transparent) Decoder(r io.Reader) (io.ReadCloser, error) {
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
	Type  int
	Guard int
}

// NewAES creates a new AES encoder/decoder.
// The aesType must be 16, 24, or 32 to select.
func NewAES(key []byte, aesType, guard int) EncodeDecoder {
	if guard > aes.BlockSize {
		panic("guard size can't be larger than aes.BlockSize")
	}

	return &AES{key, aesType, guard}
}

func (a *AES) Encoder(w io.Writer) (io.WriteCloser, error) {
	key, err := a.hdf()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
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
		W: NopCloser(w),
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
	key, err := a.hdf()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(r, iv)
	if err != nil {
		return nil, err
	}

	sr := &cipher.StreamReader{
		S: cipher.NewOFB(block, iv),
		R: r,
	}

	guard := make([]byte, a.Guard)

	_, err = io.ReadFull(sr, guard)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(guard, iv[:a.Guard]) {
		return nil, ErrAESDecode
	}

	return io.NopCloser(sr), nil
}

func (a *AES) hdf() ([]byte, error) {
	hkdf := hkdf.New(sha256.New, a.Key, nil, nil)
	key := make([]byte, a.Type)
	_, err := io.ReadFull(hkdf, key)
	return key, err
}
