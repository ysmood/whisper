package piper

import (
	"io"

	"github.com/ysmood/byframe/v4"
)

type EndErrors []byte

func (e EndErrors) Error() string {
	return string(e)
}

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

func (e Ender) End(msg []byte) error {
	return e.w.End(msg)
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
		return n, err
	}

	n, err = w.w.Write(byframe.Encode(p))
	if err != nil {
		return n, err
	}

	return len(p), nil
}

func (w WriteEnder) Close() error {
	return w.w.Close()
}

func (w WriteEnder) End(msg []byte) error {
	_, err := w.w.Write(byframe.Encode([]byte{1}))
	if err != nil {
		return err
	}

	_, err = w.w.Write(byframe.Encode(msg))
	return err
}

type ReadEnder struct {
	r io.Reader
}

func NewReadEnder(r io.Reader) *ReadEnder {
	s := byframe.NewScanner(r)

	return &ReadEnder{r: NewTransformer(func() ([]byte, error) {
		b, err := s.Next()
		if err != nil {
			return nil, err
		}

		hasErr := b[0] == 1

		b, err = s.Next()
		if err != nil {
			return nil, err
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
