package secure_test

import (
	"bytes"
	"crypto/x509"
	"testing"

	"github.com/ysmood/got"
	"github.com/ysmood/whisper/lib/secure"
	"golang.org/x/crypto/ssh"
)

func getPubKey(g got.G, file string) secure.KeyWithFilter {
	return secure.KeyWithFilter{
		Key:    g.Read(file).Bytes(),
		Filter: "",
	}
}

func TestBasic(t *testing.T) {
	g := got.T(t)

	private1, public1 := g.Read("test_data/id_ecdsa01").Bytes(), getPubKey(g, "test_data/id_ecdsa01.pub")
	private2, public2 := g.Read("test_data/id_ecdsa02").Bytes(), getPubKey(g, "test_data/id_ecdsa02.pub")
	private3, public3 := g.Read("test_data/id_ecdsa03").Bytes(), getPubKey(g, "test_data/id_ecdsa03.pub")

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
		getPubKey(g, "test_data/id_ecdsa.pub"),
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
		getPubKey(g, "test_data/id_rsa02.pub"),
	)
	g.E(err)

	key02, err := secure.New(
		g.Read("test_data/id_rsa02").Bytes(),
		"test",
		getPubKey(g, "test_data/id_rsa01.pub"),
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

	private, public := g.Read("test_data/id_ecdsa").Bytes(), getPubKey(g, "test_data/id_ecdsa.pub")

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

	private, public := g.Read("test_data/id_ecdsa").Bytes(), getPubKey(g, "test_data/id_ecdsa.pub")

	key, err := secure.New(private, "test", public)
	g.E(err)

	signed, err := key.Sign(data)
	g.E(err)

	rest, valid := key.Verify(signed)
	g.True(valid)

	g.Eq(rest, data)
}

func TestWrongPassphrase(t *testing.T) {
	g := got.T(t)

	_, err := secure.SSHPrvKey(g.Read("test_data/id_ecdsa").Bytes(), "wrong")
	g.Eq(err, x509.IncorrectPasswordError)
	g.True(secure.IsAuthErr(err))

	_, err = secure.SSHPrvKey(g.Read("test_data/id_ecdsa").Bytes(), "")
	e := &ssh.PassphraseMissingError{}
	g.Eq(err.Error(), e.Error())
}

func TestBelongs(t *testing.T) {
	g := got.T(t)

	g.True(secure.Belongs(
		getPubKey(g, "test_data/id_ecdsa.pub"),
		g.Read("test_data/id_ecdsa").Bytes(),
		"test",
	))

	g.True(secure.Belongs(
		getPubKey(g, "test_data/id_rsa01.pub"),
		g.Read("test_data/id_rsa01").Bytes(),
		"test",
	))
}
