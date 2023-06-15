package whisper_test

import (
	"fmt"
	"testing"

	"github.com/ysmood/got"
	whisper "github.com/ysmood/whisper/lib"
)

func ExampleNew() {
	senderPublic, senderPrivate, _ := whisper.GenKeysInBase64("sender's secret")

	receiverPublic, receiverPrivate, _ := whisper.GenKeysInBase64("receiver's secret")

	enc, _ := whisper.EncodeString(senderPrivate, receiverPublic, "hello world!")

	dec, _ := whisper.DecodeString(receiverPrivate, senderPublic, enc)

	fmt.Println(dec)

	// Output: hello world!
}

func TestEncrypt(t *testing.T) {
	g := got.T(t)

	data := g.RandStr(10000)

	public, private, err := whisper.GenKeysInBase64("test")
	g.E(err)

	enc, err := whisper.EncodeString(private, public, data)
	g.E(err)

	dec, err := whisper.DecodeString(private, public, enc)
	g.E(err)

	g.Eq(dec, data)
}
