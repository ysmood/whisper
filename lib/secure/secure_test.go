package secure_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
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
		g.Len(buf.Bytes(), 218)
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

	g.Eq(buf.Len(), 89)

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

	g.Eq(buf.Len(), 410)

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
		pub01, err := secure.SSHPubKey(g.Read(file + secure.PUB_KEY_EXT).Bytes())
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

func TestGenerateKeyFile(t *testing.T) {
	g := got.T(t)

	g.MkdirAll(0, "tmp")

	p := "tmp/id_ed25519"

	g.E(secure.GenerateKeyFile(false, p, "pc", "pass"))

	pub, err := secure.SSHPubKey(g.Read(p + secure.PUB_KEY_EXT).Bytes())
	g.E(err)
	g.Is(pub, ed25519.PublicKey{})

	prv, err := secure.SSHPrvKey(g.Read(p).Bytes(), "pass")
	g.E(err)
	g.Is(prv, ed25519.PrivateKey{})
}

func TestGenerateDeterministicKeyFile(t *testing.T) {
	g := got.T(t)

	g.MkdirAll(0, "tmp")

	p := "tmp/id_ed25519_deterministic"

	g.E(secure.GenerateKeyFile(true, p, "pc", "pass"))

	pub := g.Read(p + secure.PUB_KEY_EXT).Bytes()

	g.E(secure.GenerateKeyFile(true, p, "pc", "pass"))

	prv := g.Read(p).Bytes()

	yes, err := secure.Belongs(pub, prv, "pass")
	g.E(err)
	g.True(yes)
}

func TestKeyHash(t *testing.T) {
	g := got.T(t)

	check := func(path, hash string) {
		g.Helper()

		pub, err := secure.SSHPubKey(g.Read(path).Bytes())
		g.E(err)

		h, err := secure.PublicKeyHash(pub)
		g.E(err)

		g.Eq(hex.EncodeToString(h), hash)
	}

	check("test_data/id_ecdsa01.pub", "a1d24659785b9fd248b96cb130eabec6")
	check("test_data/id_rsa01.pub", "b2992973edd01b725c64df76d5a14a72")
	check("test_data/id_ed25519_01.pub", "eed9252ded1ec307bdeebfe627842175")
}
