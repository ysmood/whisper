package piper

import (
	"errors"
	"fmt"
	"io"
)

type Transformer struct {
	Transform func() ([]byte, error)

	buf []byte
}

func NewTransformer(t func() ([]byte, error)) *Transformer {
	return &Transformer{
		Transform: t,
	}
}

func (t *Transformer) Read(p []byte) (n int, err error) {
	if t.buf != nil {
		n = copy(p, t.buf)

		if n < len(t.buf) {
			t.buf = t.buf[n:]
			return
		}

		t.buf = nil
		return
	}

	b, err := t.Transform()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, io.EOF
		}

		return 0, fmt.Errorf("transformation failed: %w", err)
	}

	n = copy(p, b)

	if n < len(b) {
		t.buf = b[n:]
		return
	}

	t.buf = nil

	return
}
