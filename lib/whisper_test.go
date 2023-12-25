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

	receiver01, receiver01Pub := whisper.PrivateKey{read("id_ecdsa01"), "test"}, read("id_ecdsa01.pub")
	receiver02, receiver02Pub := whisper.PrivateKey{read("id_ecdsa02"), "test"}, read("id_ecdsa02.pub")

	// Encrypt the message that can be decrypted by both receiver01 and receiver02.
	enc, _ := whisper.EncodeString("hello world!", sender, receiver01Pub, receiver02Pub)

	dec01, _ := whisper.DecodeString(enc, receiver01, senderPub)
	dec02, _ := whisper.DecodeString(enc, receiver02, senderPub)

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
