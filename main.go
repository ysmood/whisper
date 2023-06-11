package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"

	whisper "github.com/ysmood/whisper/lib"
	"github.com/ysmood/whisper/lib/secure"
	"golang.org/x/term"
)

func main() {
	flags := flag.NewFlagSet("whisper", flag.ExitOnError)

	decryptMode := flags.Bool("d", false, "decrypt mode")
	privateKeyPath := flags.String("k", "ecdh", "private key path")

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

	var src io.Reader
	var dst io.WriteCloser
	if *decryptMode {
		src, err = whisper.Decrypt(getKey(false, *privateKeyPath), pass, getInput(flags.Arg(0)))
		dst = output(*outputFile)
	} else {
		src = getInput(flags.Arg(0))
		dst, err = whisper.Encrypt(getKey(true, *privateKeyPath), output(*outputFile), *compressLevel)
	}
	if err != nil {
		panic(err)
	}

	_, err = io.Copy(dst, src)
	if err != nil {
		panic(err)
	}
	err = dst.Close()
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

func getInput(input string) io.Reader {
	if input == "" {
		return os.Stdin
	}

	f, err := os.Open(input)
	if err != nil {
		panic(err)
	}
	return f
}

func output(file string) io.WriteCloser {
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
	private, public, err := secure.GenKeys(passphrase)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(out, []byte(whisper.Base64Encoding.EncodeToString(private)), 0o600)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(out+".pub", []byte(whisper.Base64Encoding.EncodeToString(public)), 0o600)
	if err != nil {
		panic(err)
	}

	fmt.Println("Keys generated successfully:", out)
}
