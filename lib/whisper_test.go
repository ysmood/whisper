package whisper_test

import (
	"testing"

	"github.com/ysmood/got"
	whisper "github.com/ysmood/whisper/lib"
)

func TestEncrypt(t *testing.T) {
	g := got.T(t)

	public, private, err := whisper.GenKeysBase64("test")
	g.E(err)

	enc, err := whisper.EncryptString(public, "hello world!")
	g.E(err)

	dec, err := whisper.DecryptString(private, "test", enc)
	g.E(err)

	g.Eq(dec, "hello world!")
}
