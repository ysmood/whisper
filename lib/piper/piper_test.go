package piper_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"testing"

	"github.com/ysmood/got"
	"github.com/ysmood/whisper/lib/piper"
)

func TestEncodings(t *testing.T) {
	g := got.T(t)

	trans := &piper.Transparent{}
	gzip := piper.NewGzip()
	aes := piper.NewAES(g.RandBytes(32), 0)
	base64 := piper.NewBase64()

	buf := bytes.NewBuffer(nil)

	enc, err := piper.Join(gzip, trans, piper.Join(aes, base64), trans).Encoder(buf)
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

	dec, err := ed.Decoder(buf)
	g.E(err)

	g.Eq(g.Read(dec).Bytes(), []byte("ok"))
}

func TestAESWrongSecret(t *testing.T) {
	g := got.T(t)

	encrypted := bytes.NewBuffer(nil)

	keyA := g.RandBytes(16)

	enc, err := piper.NewAES(keyA, 4).Encoder(encrypted)
	g.E(err)

	g.E(enc.Write([]byte("ok")))
	g.E(enc.Close())

	dec, err := piper.NewAES(g.RandBytes(24), 4).Decoder(bytes.NewBuffer(encrypted.Bytes()))
	g.Is(err, piper.ErrAESDecode)

	g.Neq(g.Read(dec).String(), "ok")

	dec, err = piper.NewAES(keyA, 4).Decoder(bytes.NewBuffer(encrypted.Bytes()))
	g.E(err)

	g.Eq(g.Read(dec).String(), "ok")
}

func TestTransformReader(t *testing.T) {
	g := got.T(t)

	test := func(n int) {
		data := bytes.Repeat([]byte("x"), n)
		count := 0

		trans := piper.NewTransformer(func() ([]byte, error) {
			if count != 0 {
				return nil, io.EOF
			}

			count++

			return data, nil
		})

		b, err := io.ReadAll(trans)
		g.E(err)

		g.Eq(b, data)
	}

	test(1)
	test(10)
	test(30)
	test(1000)
	test(3000)
}

type msgError struct {
	Message string
}

func (e msgError) Error() string {
	return e.Message
}

func TestEnder(t *testing.T) {
	g := got.T(t)

	data := g.RandBytes(10000)

	s, err := net.Listen("tcp", ":0")
	g.E(err)

	g.Go(func() {
		{
			conn, err := s.Accept()
			g.E(err)
			w := piper.NewEnder(conn)
			g.E(w.Write(data))
			g.E(w.End(nil))
			g.E(w.Close())
		}

		{
			conn, err := s.Accept()
			g.E(err)
			w := piper.NewEnder(conn)
			g.E(w.Write(data))
			g.E(w.End(msgError{"test"}))
			g.E(w.Close())
		}
	})

	{
		conn, err := net.Dial("tcp", s.Addr().String())
		g.E(err)

		r := piper.NewEnder(conn)

		b, err := io.ReadAll(r)
		g.E(err)

		g.Eq(b, data)
	}

	{
		conn, err := net.Dial("tcp", s.Addr().String())
		g.E(err)

		r := piper.NewEnder(conn)

		b, err := io.ReadAll(r)
		g.Eq(b, data)
		var e msgError
		g.E(json.Unmarshal(err.(piper.EndErrors), &e)) //nolint: errorlint
		g.Eq(e.Message, "test")
	}
}
