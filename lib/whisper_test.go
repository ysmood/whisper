package whisper_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ysmood/got"
	whisper "github.com/ysmood/whisper/lib"
)

func ExampleNew() {
	sender, senderPub := whisper.PrivateKey{read("id_ecdsa"), "test"}, read("id_ecdsa.pub")

	recipient01, recipient01Pub := whisper.PrivateKey{read("id_ecdsa01"), "test"}, read("id_ecdsa01.pub")
	recipient02, recipient02Pub := whisper.PrivateKey{read("id_ecdsa02"), "test"}, read("id_ecdsa02.pub")

	// Encrypt the message that can be decrypted by both recipient01 and recipient02.
	enc, _ := whisper.EncodeString("hello world!", sender, recipient01Pub, recipient02Pub)

	dec01, _ := whisper.DecodeString(enc, recipient01, senderPub)
	dec02, _ := whisper.DecodeString(enc, recipient02, senderPub)

	fmt.Println(dec01, dec02)

	// Output: hello world! hello world!
}

func TestSendToSelf(t *testing.T) {
	g := got.T(t)

	data := g.RandStr(10000)

	private, public := whisper.PrivateKey{read("id_ecdsa"), "test"}, read("id_ecdsa.pub")

	enc, err := whisper.EncodeString(data, private, public)
	g.E(err)

	dec, err := whisper.DecodeString(enc, private, public)
	g.E(err)

	g.Eq(dec, data)
}

func read(path string) []byte {
	b, err := os.ReadFile(filepath.FromSlash("secure/test_data/" + path))
	if err != nil {
		panic(err)
	}
	return b
}
