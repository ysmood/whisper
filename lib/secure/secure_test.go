package secure_test

import (
	"bytes"
	"testing"

	"github.com/ysmood/got"
	"github.com/ysmood/whisper/lib/secure"
)

func TestBasic(t *testing.T) {
	g := got.T(t)

	private1, public1, err := secure.GenKeys("test")
	g.E(err)

	private2, public2, err := secure.GenKeys("test")
	g.E(err)

	private3, public3, err := secure.GenKeys("test")
	g.E(err)

	buf := bytes.NewBuffer(nil)

	{
		key, err := secure.New(private1, "test", public2, public3)
		g.E(err)

		enc, err := key.Cipher().Encoder(buf)
		g.E(err)
		g.E(enc.Write([]byte("ok")))
		g.E(enc.Close())
	}

	{
		key, err := secure.New(private2, "test", public1)
		g.E(err)

		dec, err := key.Cipher().Decoder(bytes.NewBuffer(buf.Bytes()))
		g.E(err)

		g.Eq(g.Read(dec).String(), "ok")
	}

	{
		key, err := secure.New(private3, "test", public1)
		g.E(err)

		dec, err := key.Cipher().Decoder(bytes.NewBuffer(buf.Bytes()))
		g.E(err)

		g.Eq(g.Read(dec).String(), "ok")
	}
}

func TestSelfPrivateKey(t *testing.T) {
	g := got.T(t)

	private, public, err := secure.GenKeys("test")
	g.E(err)

	key, err := secure.New(private, "test", public)
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

	private, public, err := secure.GenKeys("test")
	g.E(err)

	key, err := secure.New(private, "test", public)
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

func TestECDH(t *testing.T) {
	g := got.T(t)

	private1, err := secure.GenKey()
	g.E(err)

	private2, err := secure.GenKey()
	g.E(err)

	aes1, err := secure.ECDH(private1, &private2.PublicKey)
	g.E(err)

	aes2, err := secure.ECDH(private2, &private1.PublicKey)
	g.E(err)

	g.Eq(aes1, aes2)
}
