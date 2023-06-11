package whisper

import (
	"encoding/base64"
	"io"
)

var Base64Encoding = base64.RawURLEncoding

type CloseWriters struct {
	w      io.Writer
	others []io.Writer
}

func NewCloseWriters(w io.Writer, others ...io.Writer) *CloseWriters {
	return &CloseWriters{w, others}
}

func (cw *CloseWriters) Write(p []byte) (n int, err error) {
	return cw.w.Write(p)
}

func (cw *CloseWriters) Close() error {
	for _, w := range cw.others {
		if c, ok := w.(io.Closer); ok {
			err := c.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

type CloseReaders struct {
	r      io.Reader
	others []io.Reader
}

func NewCloseReaders(r io.Reader, others ...io.Reader) *CloseReaders {
	return &CloseReaders{r, others}
}

func (cr *CloseReaders) Read(p []byte) (n int, err error) {
	return cr.r.Read(p)
}

func (cr *CloseReaders) Close() error {
	for _, r := range cr.others {
		if c, ok := r.(io.Closer); ok {
			err := c.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}
