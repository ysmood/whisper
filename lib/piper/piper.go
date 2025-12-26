package piper

import (
	"fmt"
	"io"
)

type EncodeDecoder interface {
	// Encoder returns a writer that will encode data to out.
	// When the Close method is called, it should not close the underlying writer,
	// it should only flush the pending data from buffer.
	Encoder(out io.Writer) (io.WriteCloser, error)

	// Decoder returns a reader that will decode the data from in.
	Decoder(in io.Reader) (io.ReadCloser, error)
}

type EncodeDecoderFn struct {
	E func(io.Writer) (io.WriteCloser, error)
	D func(io.Reader) (io.ReadCloser, error)
}

func (ed *EncodeDecoderFn) Encoder(w io.Writer) (io.WriteCloser, error) {
	return ed.E(w)
}

func (ed *EncodeDecoderFn) Decoder(r io.Reader) (io.ReadCloser, error) {
	return ed.D(r)
}

func Join(list ...EncodeDecoder) EncodeDecoder {
	return &EncodeDecoderFn{
		E: func(w io.Writer) (io.WriteCloser, error) {
			wc := &writeClosers{Writer: w}
			for i := len(list) - 1; i >= 0; i-- {
				w, err := list[i].Encoder(wc.Writer)
				if err != nil {
					return nil, fmt.Errorf("failed to create encoder at index %d: %w", i, err)
				}
				wc.Writer = w
				wc.closers = append(wc.closers, w)
			}
			return wc, nil
		},
		D: func(r io.Reader) (io.ReadCloser, error) {
			rc := &readClosers{Reader: r}
			for i := len(list) - 1; i >= 0; i-- {
				r, err := list[i].Decoder(rc.Reader)
				if err != nil {
					return nil, fmt.Errorf("failed to create decoder at index %d: %w", i, err)
				}
				rc.Reader = r
				rc.closers = append(rc.closers, r)
			}
			return rc, nil
		},
	}
}

type writeClosers struct {
	io.Writer
	closers []io.Closer
}

func (wc *writeClosers) Close() error {
	for i := len(wc.closers) - 1; i >= 0; i-- {
		err := wc.closers[i].Close()
		if err != nil {
			return err
		}
	}
	return nil
}

type readClosers struct {
	io.Reader
	closers []io.Closer
}

func (rc *readClosers) Close() error {
	for i := len(rc.closers) - 1; i >= 0; i-- {
		err := rc.closers[i].Close()
		if err != nil {
			return err
		}
	}
	return nil
}

type WriteClose struct {
	W func(p []byte) (n int, err error)
	C func() error
}

var _ io.WriteCloser = WriteClose{}

func (wc WriteClose) Write(p []byte) (n int, err error) {
	return wc.W(p)
}

func (wc WriteClose) Close() error {
	return wc.C()
}

type ReadClose struct {
	R func(p []byte) (n int, err error)
	C func() error
}

var _ io.ReadCloser = ReadClose{}

func (rc ReadClose) Read(p []byte) (n int, err error) {
	return rc.R(p)
}

func (rc ReadClose) Close() error {
	return rc.C()
}

type Buffer []byte

// Consume consumes the buffer to dst and returns the number of bytes consumed.
func (b *Buffer) Consume(dst []byte) int {
	n := copy(dst, *b)
	*b = (*b)[n:]
	return n
}
