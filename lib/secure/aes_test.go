package secure_test

import (
	"testing"

	"github.com/ysmood/got"
	"github.com/ysmood/whisper/lib/secure"
)

func TestAESCipher(t *testing.T) {
	g := got.T(t)

	check := func(size int) {
		key := g.RandBytes(16)
		data := g.RandBytes(size)

		en, err := secure.EncryptAES(key, data, 16, 2)
		g.E(err)

		de, err := secure.DecryptAES(key, en, 16, 2)
		g.E(err)

		g.Eq(de, data)
	}

	check(0)
	check(2)
	check(100)
}
