package piper_test

import (
	"bytes"
	"testing"

	"github.com/ysmood/got"
	"github.com/ysmood/whisper/lib/piper"
)

func TestEncodings(t *testing.T) {
	g := got.T(t)

	gzip := piper.NewGzip()
	aes := piper.NewAES([]byte("123"))
	base64 := piper.NewBase64()

	buf := bytes.NewBuffer(nil)

	enc, err := piper.Join(gzip, piper.Join(aes, base64)).Encoder(buf)
	g.E(err)

	g.E(enc.Write([]byte("ok")))
	g.E(enc.Close())

	dec, err := piper.Join(gzip, piper.Join(aes, base64)).Decoder(buf)
	g.E(err)

	g.Eq(g.Read(dec).Bytes(), []byte("ok"))
}

func TestOrder(t *testing.T) {
	g := got.T(t)

	gzip := piper.NewGzip()
	base64 := piper.NewBase64()

	buf := bytes.NewBuffer(nil)

	ed := piper.Join(gzip, base64)

	enc, err := ed.Encoder(buf)
	g.E(err)

	g.E(enc.Write([]byte("ok")))
	g.E(enc.Close())

	g.Eq(buf.String(), "H4sIAAAAAAAA/8rPBgQAAP//R93ceQIAAAA=")

	dec, err := ed.Decoder(buf)
	g.E(err)

	g.Eq(g.Read(dec).Bytes(), []byte("ok"))
}

func TestAESWrongSecret(t *testing.T) {
	g := got.T(t)

	encrypted := bytes.NewBuffer(nil)

	enc, err := piper.NewAES([]byte("a")).Encoder(encrypted)
	g.E(err)

	g.E(enc.Write([]byte("ok")))
	g.E(enc.Close())

	dec, err := piper.NewAES([]byte("b")).Decoder(bytes.NewBuffer(encrypted.Bytes()))
	g.Is(err, piper.ErrAESDecode)

	g.Neq(g.Read(dec).String(), "ok")

	dec, err = piper.NewAES([]byte("a")).Decoder(bytes.NewBuffer(encrypted.Bytes()))
	g.E(err)

	g.Eq(g.Read(dec).String(), "ok")
}
