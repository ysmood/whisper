package secure_test

import (
	"bytes"
	"testing"

	"github.com/ysmood/got"
	"github.com/ysmood/whisper/lib/secure"
)

func TestAESCipher(t *testing.T) {
	g := got.T(t)

	check := func(size int) {
		key := g.RandBytes(16)
		data := g.RandBytes(size)

		buf := bytes.NewBuffer(nil)
		en, err := secure.NewAESEncrypter(key, buf)
		g.E(err)
		g.E(en.Write(data))

		de, err := secure.NewAESDecrypter(key, buf)
		g.E(err)

		g.Eq(g.Read(de).Bytes(), data)
	}

	check(0)
	check(2)
	check(100)
}
