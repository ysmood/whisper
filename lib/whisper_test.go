package whisper_test

import (
	"fmt"
	"testing"

	"github.com/ysmood/got"
	whisper "github.com/ysmood/whisper/lib"
)

func ExampleNew() {
	senderPrivate, senderPublic, _ := whisper.GenKeysInBase64("sender's secret")

	receiver01Private, receiver01Public, _ := whisper.GenKeysInBase64("receiver01's secret")
	receiver02Private, receiver02Public, _ := whisper.GenKeysInBase64("receiver02's secret")

	// Encrypt the message that can be decrypted by both receiver01 and receiver02.
	enc, _ := whisper.EncodeString("hello world!", senderPrivate, receiver01Public, receiver02Public)

	dec01, _ := whisper.DecodeString(enc, receiver01Private, senderPublic)
	dec02, _ := whisper.DecodeString(enc, receiver02Private, senderPublic)

	fmt.Println(dec01, dec02)

	// Output: hello world! hello world!
}

func TestSendToSelf(t *testing.T) {
	g := got.T(t)

	data := g.RandStr(10000)

	private, public, err := whisper.GenKeysInBase64("test")
	g.E(err)

	enc, err := whisper.EncodeString(data, private, public)
	g.E(err)

	dec, err := whisper.DecodeString(enc, private, public)
	g.E(err)

	g.Eq(dec, data)
}
