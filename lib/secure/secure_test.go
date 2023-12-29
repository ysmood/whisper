package secure_test

import (
	"bytes"
	"crypto/x509"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
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

func TestSSHKey_ed25519(t *testing.T) {
	g := got.T(t)

	key01, err := secure.New(
		g.Read("test_data/id_ed25519_01").Bytes(),
		"test",
		getPubKey(g, "test_data/id_ed25519_02.pub"),
	)
	g.E(err)

	key02, err := secure.New(
		g.Read("test_data/id_ed25519_02").Bytes(),
		"",
		getPubKey(g, "test_data/id_ed25519_01.pub"),
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

func TestSharedSecret(t *testing.T) {
	g := got.T(t)

	check := func(file string) {
		aesKey := g.RandBytes(32)

		prv01, err := secure.SSHPrvKey(g.Read(file).Bytes(), "test")
		g.E(err)
		pub01, err := secure.SSHPubKey(g.Read(file + ".pub").Bytes())
		g.E(err)

		encrypted, err := secure.EncryptSharedSecret(aesKey, pub01)
		g.E(err)

		decrypted, err := secure.DecryptSharedSecret(encrypted, prv01)
		g.E(err)

		g.Eq(decrypted, aesKey)
	}

	check("test_data/id_ecdsa01")
	check("test_data/id_ed25519_01")
	check("test_data/id_rsa01")
}

func TestKeyTypes(t *testing.T) {
	g := got.T(t)

	check := func(file string) {
		g.Helper()

		pub, err := secure.SSHPubKey(g.Read(file).Bytes())
		g.E(err)

		ms := regexp.MustCompile(`(\d+).pub`).FindStringSubmatch(file)
		size, err := strconv.ParseInt(ms[1], 10, 64)
		g.E(err)

		g.Desc(file).Eq(secure.PublicKeySize(pub), size)

		file = strings.TrimSuffix(file, ".pub")

		prv, err := secure.SSHPrvKey(g.Read(file).Bytes(), "")
		g.E(err)

		g.Desc(file).Eq(secure.PrivateKeySize(prv), size)

		sharedPub, err := secure.FindPubSharedKey(prv)
		g.E(err)
		g.Eq(sharedPub, pub)

		sharedPrv, err := secure.FindPrvSharedKey(pub)
		g.E(err)
		g.Eq(sharedPrv, prv)
	}

	ms, err := filepath.Glob("shared-keys/*.pub")
	g.E(err)

	for _, p := range ms {
		check(p)
	}
}
