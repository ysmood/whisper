package piper

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ysmood/byframe/v4"
)

type EndErrors []byte

func (e EndErrors) Error() string {
	return string(e)
}

// Ender acts like a proxy for the a io.ReadWriteCloser.
// The writer can send [EndErrors] to the reader.
// It will use json to marshal the error for the reader.
type Ender struct {
	w *WriteEnder
	r *ReadEnder
}

func NewEnder(rw io.ReadWriteCloser) *Ender {
	return &Ender{
		w: NewWriteEnder(rw),
		r: NewReadEnder(rw),
	}
}

func (e Ender) Read(p []byte) (n int, err error) {
	return e.r.Read(p)
}

func (e Ender) Write(p []byte) (n int, err error) {
	return e.w.Write(p)
}

func (e Ender) Close() error {
	return e.w.Close()
}

func (e Ender) End(err error) error {
	return e.w.End(err)
}

type WriteEnder struct {
	w io.WriteCloser
}

func NewWriteEnder(w io.WriteCloser) *WriteEnder {
	return &WriteEnder{w}
}

func (w WriteEnder) Write(p []byte) (n int, err error) {
	n, err = w.w.Write(byframe.Encode([]byte{0}))
	if err != nil {
		return n, fmt.Errorf("failed to write frame header: %w", err)
	}

	n, err = w.w.Write(byframe.Encode(p))
	if err != nil {
		return n, fmt.Errorf("failed to write frame data: %w", err)
	}

	return len(p), nil
}

func (w WriteEnder) Close() error {
	return w.w.Close()
}

func (w WriteEnder) End(e error) error {
	_, err := w.w.Write(byframe.Encode([]byte{1}))
	if err != nil {
		return fmt.Errorf("failed to write end marker: %w", err)
	}

	var b []byte
	if e != nil {
		b, err = json.Marshal(e)
		if err != nil {
			return fmt.Errorf("failed to marshal error: %w", err)
		}
	}

	_, err = w.w.Write(byframe.Encode(b))
	if err != nil {
		return fmt.Errorf("failed to write end data: %w", err)
	}
	return nil
}

type ReadEnder struct {
	r io.Reader
}

func NewReadEnder(r io.Reader) *ReadEnder {
	s := byframe.NewScanner(r)

	return &ReadEnder{r: NewTransformer(func() ([]byte, error) {
		b, err := s.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to read frame header: %w", err)
		}

		hasErr := b[0] == 1

		b, err = s.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to read frame data: %w", err)
		}

		if hasErr {
			if len(b) == 0 {
				return nil, io.EOF
			}

			return nil, EndErrors(b)
		}

		return b, nil
	})}
}

func (r ReadEnder) Read(p []byte) (n int, err error) {
	return r.r.Read(p)
}
