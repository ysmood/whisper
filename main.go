package main

import (
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	whisper "github.com/ysmood/whisper/lib"
	"github.com/ysmood/whisper/lib/piper"
	"github.com/ysmood/whisper/lib/secure"
	"golang.org/x/term"
)

const defaultKeyName = "ecc_key"

func main() {
	flags := flag.NewFlagSet("whisper", flag.ExitOnError)

	decryptMode := flags.Bool("d", false, "decrypt mode")
	publicKey := flags.String("p", "",
		"the public key for encryption or signature checking, it can be a local file path or https url")
	ignoreSignErr := flags.Bool("i", false, "ignore signature error")
	privateKeyPath := flags.String("k", defaultKeyName, "private key path")
	bin := flags.Bool("b", false, "encoding data as binary instead of base64")

	compressLevel := flags.Int("c", gzip.DefaultCompression, "gzip compression level")

	keyGen := flags.Bool("g", false, "generate a pair of ecc private and public keys")
	passphrase := flags.Bool("s", false, "prompt secret passphrase input for private key")

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
		whisper.PublicKey(getPublicKey(*publicKey, pubKeyName(*privateKeyPath))),
		whisper.PrivateKey{
			Data:       getKey(*privateKeyPath),
			Passphrase: pass,
		},
		*compressLevel,
		!*bin,
	)
	if err != nil {
		panic(err)
	}

	process(*decryptMode, *ignoreSignErr, wp, getInput(flags.Arg(0)), getOutput(*outputFile))
}

func process(decrypt, ignoreSignErr bool, wp piper.EncodeDecoder, in io.ReadCloser, out io.WriteCloser) {
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
	if err != nil && !(ignoreSignErr && errors.Is(err, secure.ErrSignNotMatch)) {
		panic(err)
	}
	err = out.Close()
	if err != nil {
		panic(err)
	}
}

func getKey(keyFile string) string {
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

	err = os.WriteFile(pubKeyName(out), []byte(whisper.Base64Encoding.EncodeToString(public)), 0o400)
	if err != nil {
		panic(err)
	}

	fmt.Println("Keys generated successfully:", out)
}

func getPublicKey(p, fallback string) string {
	if p == "" {
		p = fallback
	} else if strings.HasPrefix(p, "https://") {
		res, err := http.Get(p) //nolint:noctx
		if err != nil {
			panic(err)
		}
		defer func() { _ = res.Body.Close() }()

		b, err := io.ReadAll(res.Body)
		if err != nil {
			panic(err)
		}

		return string(b)
	}

	return getKey(p)
}

func pubKeyName(prv string) string {
	return prv + "_pub"
}
