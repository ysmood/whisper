<!-- markdownlint-disable MD010 -->

# Overview

A simple tool to encrypt data with a ECDH public key and decrypt it with the private key.

## Download

Go to the [release page](https://github.com/ysmood/whisper/releases).

If you have golang installed:

```bash
go install github.com/ysmood/whisper@latest
```

## Usage

```bash
whisper -g
# Keys generated successfully: ecdh

echo 'hello world!' | whisper
# FVPmYc4x1JilPtF8rMs0n2OlX2

echo 'FVPmYc4x1JilPtF8rMs0n2OlX2' | whisper -d
# hello world!
```

Use it as lib:

```go
package main

import (
	"fmt"

	"github.com/ysmood/whisper/lib"
)

func main() {
	private, public, _ := secure.GenKeysBase64("my-secret")

	enc, _ := whisper.EncryptString(public, "hello world!", 9)

	dec, _ := whisper.DecryptString(private, "test", enc)

	fmt.Println(dec) // hello world!
}
```
