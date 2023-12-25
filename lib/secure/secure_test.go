package secure_test

import (
	"bytes"
	"crypto/x509"
	"testing"

	"github.com/ysmood/got"
	"github.com/ysmood/whisper/lib/secure"
	"golang.org/x/crypto/ssh"
)

func TestBasic(t *testing.T) {
	g := got.T(t)

	private1, public1 := g.Read("test_data/id_ecdsa01").Bytes(), g.Read("test_data/id_ecdsa01.pub").Bytes()
	private2, public2 := g.Read("test_data/id_ecdsa02").Bytes(), g.Read("test_data/id_ecdsa02.pub").Bytes()
	private3, public3 := g.Read("test_data/id_ecdsa03").Bytes(), g.Read("test_data/id_ecdsa03.pub").Bytes()

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

func TestSSHKey(t *testing.T) {
	g := got.T(t)

	key, err := secure.New(
		g.Read("test_data/id_ecdsa").Bytes(),
		"test",
		g.Read("test_data/id_ecdsa.pub").Bytes(),
	)
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

func TestSSHKey_rsa(t *testing.T) {
	g := got.T(t)

	key01, err := secure.New(
		g.Read("test_data/id_rsa01").Bytes(),
		"test",
		g.Read("test_data/id_rsa02.pub").Bytes(),
	)
	g.E(err)

	key02, err := secure.New(
		g.Read("test_data/id_rsa02").Bytes(),
		"test",
		g.Read("test_data/id_rsa01.pub").Bytes(),
	)
	g.E(err)

	buf := bytes.NewBuffer(nil)
	enc, err := key01.Cipher().Encoder(buf)
	g.E(err)
	g.E(enc.Write([]byte("ok")))
	g.E(enc.Close())

	dec, err := key02.Cipher().Decoder(buf)
	g.E(err)

	g.Eq(g.Read(dec).String(), "ok")
}

func TestSelfPrivateKey(t *testing.T) {
	g := got.T(t)

	private, public := g.Read("test_data/id_ecdsa").Bytes(), g.Read("test_data/id_ecdsa.pub").Bytes()

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

	private, public := g.Read("test_data/id_ecdsa").Bytes(), g.Read("test_data/id_ecdsa.pub").Bytes()

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

func TestWrongPassphrase(t *testing.T) {
	g := got.T(t)

	_, err := secure.SSHKey(g.Read("test_data/id_ecdsa").Bytes(), "wrong")
	g.Eq(err, x509.IncorrectPasswordError)
	g.True(secure.IsAuthErr(err))

	_, err = secure.SSHKey(g.Read("test_data/id_ecdsa").Bytes(), "")
	e := &ssh.PassphraseMissingError{}
	g.Eq(err.Error(), e.Error())
}
