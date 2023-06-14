package secure_test

import (
	"bytes"
	"testing"

	"github.com/ysmood/got"
	"github.com/ysmood/whisper/lib/secure"
)

func TestBasic(t *testing.T) {
	g := got.T(t)

	public, private, err := secure.GenKeys("test")
	g.E(err)

	key, err := secure.New(public, nil, "test")
	g.E(err)

	buf := bytes.NewBuffer(nil)
	enc, err := key.Cipher().Encoder(buf)
	g.E(err)
	g.E(enc.Write([]byte("ok")))
	g.E(enc.Close())

	key, err = secure.New(nil, private, "test")
	g.E(err)

	dec, err := key.Cipher().Decoder(buf)
	g.E(err)

	g.Eq(g.Read(dec).String(), "ok")
}

func TestSelfPrivateKey(t *testing.T) {
	g := got.T(t)

	public, private, err := secure.GenKeys("test")
	g.E(err)

	key, err := secure.New(public, private, "test")
	g.E(err)

	buf := bytes.NewBuffer(nil)
	enc, err := key.Cipher().Encoder(buf)
	g.E(err)
	g.E(enc.Write([]byte("ok")))
	g.E(enc.Close())

	dec, err := key.Cipher().Decoder(buf)
	g.E(err)

	g.Eq(g.Read(dec).String(), "ok")
}

func TestSigner(t *testing.T) {
	g := got.T(t)

	data := bytes.Repeat([]byte("ok"), 10000)

	public, private, err := secure.GenKeys("test")
	g.E(err)

	key, err := secure.New(public, private, "test")
	g.E(err)

	buf := bytes.NewBuffer(nil)
	enc, err := key.Signer().Encoder(buf)
	g.E(err)
	g.E(enc.Write(data))
	g.E(enc.Close())

	dec, err := key.Signer().Decoder(buf)
	g.E(err)

	g.Eq(g.Read(dec).Bytes(), data)
}
