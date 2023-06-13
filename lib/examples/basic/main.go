package main

import (
	"fmt"

	whisper "github.com/ysmood/whisper/lib"
)

func main() {
	const secret = "my-secret"

	public, private, _ := whisper.GenKeysBase64(secret)

	enc, _ := whisper.EncryptString(public, "hello world!")

	dec, _ := whisper.DecryptString(private, secret, enc)

	fmt.Println(dec) // hello world!
}
