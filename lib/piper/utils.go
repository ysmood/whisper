package piper

import (
	"io"
	"log"
)

type nopCloser struct {
	w io.Writer
}

func NopCloser(w io.Writer) io.WriteCloser {
	return &nopCloser{w}
}

func (w *nopCloser) Write(p []byte) (n int, err error) {
	return w.w.Write(p)
}

func (w *nopCloser) Close() error {
	return nil
}

type Debug struct {
	prefix string
	r      io.Reader
	w      io.Writer
}

func NewDebug(prefix string, r io.Reader, w io.Writer) io.ReadWriter {
	return &Debug{prefix, r, w}
}

func (d *Debug) Read(p []byte) (n int, err error) {
	n, err = d.r.Read(p)
	log.Printf("[%s] read %d %v %x", d.prefix, n, err, p[:n])
	return
}

func (d *Debug) Write(p []byte) (n int, err error) {
	n, err = d.w.Write(p)
	log.Printf("[%s] write %d %v %x", d.prefix, n, err, p[:n])
	return
}

type WrapReadCloser struct {
	Reader io.Reader
	Closer io.Closer
}

func (w *WrapReadCloser) Read(p []byte) (n int, err error) {
	return w.Reader.Read(p)
}

func (w *WrapReadCloser) Close() error {
	return w.Closer.Close()
}
