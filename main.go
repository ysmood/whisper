package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"

	whisper "github.com/ysmood/whisper/lib"
	"github.com/ysmood/whisper/lib/piper"
	"github.com/ysmood/whisper/lib/secure"
	"golang.org/x/term"
)

func main() {
	flags := flag.NewFlagSet("whisper", flag.ExitOnError)

	decryptMode := flags.Bool("d", false, "decrypt mode")
	privateKeyPath := flags.String("k", "ecdh", "private key path")
	bin := flags.Bool("b", false, "encoding data as binary instead of base64")

	compressLevel := flags.Int("c", gzip.DefaultCompression, "gzip compression level")

	keyGen := flags.Bool("g", false, "generate a pair of ecdh private and public keys")
	passphrase := flags.Bool("p", false, "prompt passphrase input for private key")

	outputFile := flags.String("o", "", "output encryption/decryption to the specified file")

	flags.Usage = func() {
		fmt.Println("Usage: whisper [options] [input file]")
		flags.PrintDefaults()
	}

	err := flags.Parse(os.Args[1:])
	if err != nil {
		panic(err)
	}

	pass := ""
	if *passphrase {
		pass = readPassphrase()
	}

	if *keyGen {
		genKeys(pass, *privateKeyPath)
		return
	}

	wp, err := whisper.New(
		getKey(true, *privateKeyPath),
		getKey(false, *privateKeyPath),
		pass,
		*compressLevel,
		!*bin,
	)
	if err != nil {
		panic(err)
	}

	process(*decryptMode, wp, getInput(flags.Arg(0)), getOutput(*outputFile))
}

func process(decrypt bool, wp piper.EncodeDecoder, in io.ReadCloser, out io.WriteCloser) {
	var err error
	if decrypt {
		in, err = wp.Decoder(in)
	} else {
		out, err = wp.Encoder(out)
	}
	if err != nil {
		panic(err)
	}

	_, err = io.Copy(out, in)
	if err != nil {
		panic(err)
	}
	err = out.Close()
	if err != nil {
		panic(err)
	}
}

func getKey(public bool, keyFile string) string {
	if public {
		keyFile += ".pub"
	}

	b, err := os.ReadFile(keyFile)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func readPassphrase() string {
	fmt.Fprint(os.Stderr, "Enter passphrase: ")
	passphrase, err := term.ReadPassword(0)
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(os.Stderr)
	return string(passphrase)
}

func getInput(input string) io.ReadCloser {
	if input == "" {
		return os.Stdin
	}

	f, err := os.Open(input)
	if err != nil {
		panic(err)
	}
	return f
}

func getOutput(file string) io.WriteCloser {
	if file == "" {
		return os.Stdout
	}

	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	return f
}

func genKeys(passphrase, out string) {
	public, private, err := secure.GenKeys(passphrase)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(out, []byte(whisper.Base64Encoding.EncodeToString(private)), 0o400)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(out+".pub", []byte(whisper.Base64Encoding.EncodeToString(public)), 0o400)
	if err != nil {
		panic(err)
	}

	fmt.Println("Keys generated successfully:", out)
}
