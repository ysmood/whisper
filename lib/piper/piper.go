package piper

import "io"

type EncodeDecoder interface {
	Encoder(io.Writer) (io.WriteCloser, error)
	Decoder(io.Reader) (io.ReadCloser, error)
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
	for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
		list[i], list[j] = list[j], list[i]
	}

	return &EncodeDecoderFn{
		E: func(w io.Writer) (io.WriteCloser, error) {
			ws := closeWriters{w}
			for _, e := range list {
				var err error
				w, err = e.Encoder(w)
				if err != nil {
					return nil, err
				}
				ws = append(closeWriters{w}, ws...)
			}
			return ws, nil
		},
		D: func(r io.Reader) (io.ReadCloser, error) {
			rs := closeReaders{r}
			for _, d := range list {
				var err error
				r, err = d.Decoder(r)
				if err != nil {
					return nil, err
				}
				rs = append(closeReaders{r}, rs...)
			}
			return rs, nil
		},
	}
}

type closeWriters []io.Writer

func (cw closeWriters) Write(p []byte) (n int, err error) {
	return cw[0].Write(p)
}

func (cw closeWriters) Close() error {
	for _, w := range cw {
		err := Close(w)
		if err != nil {
			return err
		}
	}
	return nil
}

type closeReaders []io.Reader

func (cr closeReaders) Read(p []byte) (n int, err error) {
	return cr[0].Read(p)
}

func (cr closeReaders) Close() error {
	for _, r := range cr {
		err := Close(r)
		if err != nil {
			return err
		}
	}
	return nil
}

func Close(stream interface{}) error {
	if c, ok := stream.(io.Closer); ok {
		return c.Close()
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
