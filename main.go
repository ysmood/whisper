package main

import (
	"compress/gzip"
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

	privateKey := flags.String("k", defaultKeyName, "private key path")

	var publicKeys publicKeysFlag
	flags.Var(&publicKeys, "p", "the public keys, each can be a local file path or https url")

	bin := flags.Bool("b", false, "encoding data as binary instead of base64")

	compressLevel := flags.Int("c", gzip.DefaultCompression, "gzip compression level")

	keyGen := flags.Bool("g", false, "generate a pair of ecc private and public keys")
	passphrase := flags.Bool("s", false, "prompt secret passphrase input to encrypt/decrypt private key")

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
		genKeys(pass, *privateKey)
		return
	}

	if publicKeys == nil {
		publicKeys = publicKeysFlag{pubKeyName(defaultKeyName)}
	}

	wp, err := whisper.New(
		*compressLevel,
		!*bin,
		whisper.PrivateKey{
			Data:       getKey(*privateKey),
			Passphrase: pass,
		},
		getPublicKeys(publicKeys)...,
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

func getPublicKeys(paths []string) []whisper.PublicKey {
	list := []whisper.PublicKey{}
	for _, p := range paths {
		list = append(list, whisper.PublicKey(getPublicKey(p)))
	}
	return list
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
	private, public, err := secure.GenKeys(passphrase)
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

func getPublicKey(p string) string {
	if strings.HasPrefix(p, "https://") {
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

type publicKeysFlag []string

func (i *publicKeysFlag) String() string {
	return strings.Join(*i, ", ")
}

func (i *publicKeysFlag) Set(value string) error {
	*i = append(*i, value)
	return nil
}
