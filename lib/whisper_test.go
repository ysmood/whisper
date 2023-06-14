package whisper_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ysmood/got"
	whisper "github.com/ysmood/whisper/lib"
	"github.com/ysmood/whisper/lib/secure"
)

func ExampleNew() {
	senderPublic, senderPrivate, _ := whisper.GenKeysInBase64("sender's secret")

	receiverPublic, receiverPrivate, _ := whisper.GenKeysInBase64("receiver's secret")

	enc, _ := whisper.EncodeString(senderPrivate, receiverPublic, "hello world!")

	dec, _ := whisper.DecodeString(receiverPrivate, senderPublic, enc)

	fmt.Println(dec)

	// Output: hello world!
}

func ExampleNew_signature_error() {
	public, private, _ := whisper.GenKeysInBase64("test")

	enc, _ := whisper.EncodeString(private, public, "hello world!")

	newPublic, _, _ := whisper.GenKeysInBase64("test")

	dec, err := whisper.DecodeString(private, newPublic, enc)

	fmt.Println(errors.Is(err, secure.ErrSignNotMatch))
	fmt.Println(dec)

	// Output:
	// true
	// hello world!
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

func TestEncryptWithoutSign(t *testing.T) {
	g := got.T(t)

	data := g.RandStr(10000)

	public, private, err := whisper.GenKeysInBase64("test")
	g.E(err)

	enc, err := whisper.EncodeString(private, public, data)
	g.E(err)

	newPublic, _, err := whisper.GenKeysInBase64("test")
	g.E(err)

	dec, err := whisper.DecodeString(private, newPublic, enc)
	g.Eq(err, secure.ErrSignNotMatch)

	g.Desc("we should still able to use the data even the sign does not match").Eq(dec, data)
}
