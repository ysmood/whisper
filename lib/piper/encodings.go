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
	"fmt"
	"io"
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
	Guard int
}

// NewAES creates a new AES encoder/decoder.
// The aesType must be 0, 16, 24, or 32 to select, if it's 0, no KDF will be used,
// the key will be used directly.
func NewAES(key []byte, guard int) EncodeDecoder {
	if guard > aes.BlockSize {
		panic("guard size can't be larger than aes.BlockSize")
	}

	// If the key size is not valid, use sha256 to derive a valid key.
	if len(key) != 16 || len(key) != 24 && len(key) != 32 {
		hash := sha256.Sum256(key)
		key = hash[:]
	}

	return &AES{key, guard}
}

func (a *AES) Encoder(w io.Writer) (io.WriteCloser, error) {
	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	_, err = w.Write(iv)
	if err != nil {
		return nil, fmt.Errorf("failed to write IV: %w", err)
	}

	s := &cipher.StreamWriter{
		S: cipher.NewCTR(block, iv),
		W: NopCloser(w),
	}

	// AES is resistant to known-plaintext attack.
	// We use this guard to tell if the key is correct or not before the decryption.
	// The change of failing to detect wrong key is 1/(2^(a.Guard * 8)).
	_, err = s.Write(iv[:a.Guard])
	if err != nil {
		return nil, fmt.Errorf("failed to write guard bytes: %w", err)
	}

	return s, nil
}

var ErrAESDecode = errors.New("wrong secret or corrupted data")

func (a *AES) Decoder(r io.Reader) (io.ReadCloser, error) {
	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(r, iv)
	if err != nil {
		return nil, fmt.Errorf("failed to read IV: %w", err)
	}

	sr := &cipher.StreamReader{
		S: cipher.NewCTR(block, iv),
		R: r,
	}

	guard := make([]byte, a.Guard)

	_, err = io.ReadFull(sr, guard)
	if err != nil {
		return nil, fmt.Errorf("failed to read guard bytes: %w", err)
	}

	if !bytes.Equal(guard, iv[:a.Guard]) {
		return nil, ErrAESDecode
	}

	return io.NopCloser(sr), nil
}
