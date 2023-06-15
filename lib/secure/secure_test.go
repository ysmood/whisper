package secure_test

import (
	"bytes"
	"testing"

	"github.com/ysmood/got"
	"github.com/ysmood/whisper/lib/secure"
)

func TestBasic(t *testing.T) {
	g := got.T(t)

	public1, private1, err := secure.GenKeys("test")
	g.E(err)

	public2, private2, err := secure.GenKeys("test")
	g.E(err)

	key, err := secure.New(public1, private2, "test")
	g.E(err)

	buf := bytes.NewBuffer(nil)
	enc, err := key.Cipher().Encoder(buf)
	g.E(err)
	g.E(enc.Write([]byte("ok")))
	g.E(enc.Close())

	key, err = secure.New(public2, private1, "test")
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

func TestAESKey(t *testing.T) {
	g := got.T(t)

	public1, private1, err := secure.GenKeys("1")
	g.E(err)

	public2, private2, err := secure.GenKeys("2")
	g.E(err)

	key1, err := secure.New(public2, private1, "1")
	g.E(err)

	key2, err := secure.New(public1, private2, "2")
	g.E(err)

	aes1, err := key1.AESKey()
	g.E(err)

	aes2, err := key2.AESKey()
	g.E(err)

	g.Eq(aes1, aes2)
}
