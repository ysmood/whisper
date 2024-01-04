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

func TestBasic(t *testing.T) {
	g := got.T(t)

	private1, public1 := g.Read("test_data/id_ecdsa01").Bytes(), g.Read("test_data/id_ecdsa01.pub").Bytes()
	private2, public2 := g.Read("test_data/id_ecdsa02").Bytes(), g.Read("test_data/id_ecdsa02.pub").Bytes()

	buf := bytes.NewBuffer(nil)

	{
		key, err := secure.NewCipherBytes(nil, "", 0, public1, public2)
		g.E(err)

		enc, err := key.Encoder(buf)
		g.E(err)
		g.E(enc.Write([]byte("ok")))
		g.E(enc.Close())
		g.Len(buf.Bytes(), 88)
	}

	{
		key, err := secure.NewCipherBytes(private1, "test", 0)
		g.E(err)

		dec, err := key.Decoder(bytes.NewBuffer(buf.Bytes()))
		g.E(err)

		g.Eq(g.Read(dec).String(), "ok")
	}

	{
		key, err := secure.NewCipherBytes(private2, "test", 1)
		g.E(err)

		dec, err := key.Decoder(bytes.NewBuffer(buf.Bytes()))
		g.E(err)

		g.Eq(g.Read(dec).String(), "ok")
	}
}

func TestED25519(t *testing.T) { //nolint: dupl
	g := got.T(t)

	key01, err := secure.NewCipherBytes(
		g.Read("test_data/id_ed25519_01").Bytes(),
		"test",
		0,
		g.Read("test_data/id_ed25519_02.pub").Bytes(),
	)
	g.E(err)

	key02, err := secure.NewCipherBytes(
		g.Read("test_data/id_ed25519_02").Bytes(),
		"",
		0,
		g.Read("test_data/id_ed25519_01.pub").Bytes(),
	)
	g.E(err)

	buf := bytes.NewBuffer(nil)
	enc, err := key01.Encoder(buf)
	g.E(err)
	g.E(enc.Write([]byte("ok")))
	g.E(enc.Close())

	g.Eq(buf.Len(), 55)

	dec, err := key02.Decoder(buf)
	g.E(err)

	g.Eq(g.Read(dec).String(), "ok")
}

func TestRSA(t *testing.T) { //nolint: dupl
	g := got.T(t)

	key01, err := secure.NewCipherBytes(
		g.Read("test_data/id_rsa01").Bytes(),
		"test",
		0,
		g.Read("test_data/id_rsa02.pub").Bytes(),
	)
	g.E(err)

	key02, err := secure.NewCipherBytes(
		g.Read("test_data/id_rsa02").Bytes(),
		"test",
		0,
		g.Read("test_data/id_rsa01.pub").Bytes(),
	)
	g.E(err)

	buf := bytes.NewBuffer(nil)
	enc, err := key01.Encoder(buf)
	g.E(err)
	g.E(enc.Write([]byte("ok")))
	g.E(enc.Close())

	g.Eq(buf.Len(), 408)

	dec, err := key02.Decoder(buf)
	g.E(err)

	g.Eq(g.Read(dec).String(), "ok")
}

func TestSelfPrivateKey(t *testing.T) {
	g := got.T(t)

	private, public := g.Read("test_data/id_ecdsa").Bytes(), g.Read("test_data/id_ecdsa.pub").Bytes()

	key, err := secure.NewCipherBytes(private, "test", 0, public)
	g.E(err)

	buf := bytes.NewBuffer(nil)
	enc, err := key.Encoder(buf)
	g.E(err)
	g.E(enc.Write([]byte("ok")))
	g.E(enc.Close())

	dec, err := key.Decoder(buf)
	g.E(err)

	g.Eq(g.Read(dec).String(), "ok")
}

func TestSigner(t *testing.T) {
	g := got.T(t)

	data := bytes.Repeat([]byte("ok"), 10000)

	private, public := g.Read("test_data/id_ecdsa").Bytes(), g.Read("test_data/id_ecdsa.pub").Bytes()

	key, err := secure.NewSignerBytes(private, "test")
	g.E(err)

	signed, err := key.Sign(data)
	g.E(err)

	key, err = secure.NewSignerBytes(nil, "", public)
	g.E(err)

	rest, valid := key.Verify(signed)
	g.True(valid)

	g.Eq(rest, data)

	key, err = secure.NewSignerBytes(nil, "")
	g.E(err)
	rest, valid = key.Verify(signed)
	g.False(valid)
	g.Eq(rest, data)
}

func TestWrongPassphrase(t *testing.T) {
	g := got.T(t)

	_, err := secure.SSHPrvKey(g.Read("test_data/id_ecdsa").Bytes(), "wrong")
	g.Is(err, x509.IncorrectPasswordError)
	g.True(secure.IsAuthErr(err))

	_, err = secure.SSHPrvKey(g.Read("test_data/id_ecdsa").Bytes(), "")
	e := &ssh.PassphraseMissingError{}
	g.Has(err.Error(), e.Error())
}

func TestSharedSecret(t *testing.T) {
	g := got.T(t)

	check := func(file string) {
		aesKey := g.RandBytes(32)

		prv01, err := secure.SSHPrvKey(g.Read(file).Bytes(), "test")
		g.E(err)
		pub01, err := secure.SSHPubKey(g.Read(file + ".pub").Bytes())
		g.E(err)

		encrypted, err := secure.EncryptSharedSecret(aesKey, 16, pub01)
		g.E(err)

		decrypted, err := secure.DecryptSharedSecret(encrypted, 16, prv01)
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

func TestBelongs(t *testing.T) {
	g := got.T(t)

	ok, err := secure.Belongs(
		g.Read("test_data/id_ecdsa.pub").Bytes(),
		g.Read("test_data/id_ecdsa").Bytes(),
		"test",
	)
	g.E(err)
	g.True(ok)

	ok, err = secure.Belongs(
		g.Read("test_data/id_rsa01.pub").Bytes(),
		g.Read("test_data/id_rsa01").Bytes(),
		"test",
	)
	g.E(err)
	g.True(ok)

	ok, err = secure.Belongs(
		g.Read("test_data/id_ed25519_01.pub").Bytes(),
		g.Read("test_data/id_ed25519_01").Bytes(),
		"test",
	)
	g.E(err)
	g.True(ok)
}
