package secure_test

import (
	"bytes"
	"testing"

	"github.com/ysmood/got"
	"github.com/ysmood/whisper/lib/secure"
)

func TestECDH(t *testing.T) {
	g := got.T(t)

	private, public, err := secure.GenKeys("test")
	g.E(err)

	publicKey, err := secure.LoadPublicKey(public)
	g.E(err)

	encrypted := bytes.NewBuffer(nil)
	enc, err := secure.Encrypt(publicKey, encrypted)
	g.E(err)
	g.E(enc.Write([]byte("ok")))

	privateKey, err := secure.LoadPrivateKey("test", private)
	g.E(err)

	decrypted, err := secure.Decrypt(privateKey, encrypted)
	g.E(err)

	g.Eq(g.Read(decrypted).String(), "ok")
}

func TestKey(t *testing.T) {
	g := got.T(t)

	private, public, err := secure.GenKeys("test")
	g.E(err)

	publicKey, err := secure.LoadPublicKey(public)
	g.E(err)

	aesKey, encryptedKey, err := publicKey.Generate()
	g.E(err)

	privateKey, err := secure.LoadPrivateKey("test", private)
	g.E(err)

	out, err := privateKey.Decrypt(encryptedKey)
	g.E(err)
	g.Eq(aesKey, out)

	outAgain, err := privateKey.Decrypt(encryptedKey)
	g.E(err)

	g.Eq(aesKey, outAgain)
}
