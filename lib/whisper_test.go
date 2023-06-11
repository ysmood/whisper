package whisper_test

import (
	"bytes"
	"testing"

	"github.com/ysmood/got"
	whisper "github.com/ysmood/whisper/lib"
)

func TestBasic(t *testing.T) {
	g := got.T(t)

	private, public, err := whisper.GenKeysBase64("test")
	g.E(err)

	encrypted := bytes.NewBuffer(nil)

	en, err := whisper.Encrypt(public, encrypted, 0)
	g.E(err)

	g.E(en.Write([]byte("ok")))
	g.E(en.Close())

	de, err := whisper.Decrypt(private, "test", encrypted)
	g.E(err)

	g.Eq(g.Read(de).String(), "ok")
}

func TestEncrypt(t *testing.T) {
	g := got.T(t)

	private, public, err := whisper.GenKeysBase64("test")
	g.E(err)

	enc, err := whisper.EncryptString(public, "hello world!", 9)
	g.E(err)

	dec, err := whisper.DecryptString(private, "test", enc)
	g.E(err)

	g.Eq(dec, "hello world!")
}
