package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"os"

	whisper "github.com/ysmood/whisper/lib"
)

func main() { //nolint: funlen
	flags := flag.NewFlagSet("whisper", flag.ExitOnError)

	version := flags.Bool("v", false, "print version")

	clearCache := flags.Bool("clear-cache", false, "clear the cache")

	decryptMode := flags.Bool("d", false, "decrypt mode")

	agent := flags.Bool(AGENT_FLAG, false,
		"run as agent, you can use WHISPER_AGENT_ADDR to specify the host and port to listen on")

	privateKey := flags.String("k", DEFAULT_KEY_NAME, "private key path")
	passphrase := flags.String("s", "", "passphrase to decrypt the private key")

	addPublicKey := flags.String("a", "",
		`add public key to the beginning of the output, can be a local file path,`+
			` "@{GITHUB_ID}", "@{HTTPS_URL}, or "." for the default key`)

	var publicKeys publicKeysFlag
	flags.Var(&publicKeys, "p", `the public keys, each can be a local file path, "@{GITHUB_ID}", or "@{HTTPS_URL}"`)

	bin := flags.Bool("b", false, "encoding data as binary instead of base64")

	compressLevel := flags.Int("c", gzip.DefaultCompression, "gzip compression level")

	outputFile := flags.String("o", "", "output encryption/decryption to the specified file")

	flags.Usage = func() {
		fmt.Println("Usage: whisper [options] [input file]")
		flags.PrintDefaults()
	}

	err := flags.Parse(os.Args[1:])
	if err != nil {
		panic(err)
	}

	if *version {
		fmt.Println("version:", whisper.Version())
		return
	}

	if *clearCache {
		cacheClear()
		return
	}

	if *agent {
		runAsAgent()
		return
	}

	startAgent()

	if publicKeys == nil {
		if *decryptMode {
			DEFAULT_KEY_NAME = *privateKey
		} else {
			publicKeys = publicKeysFlag{pubKeyName(*privateKey)}
		}
	}

	conf := whisper.Config{
		GzipLevel: *compressLevel,
		Base64:    !*bin,
		Private: whisper.PrivateKey{
			Data:       getKey(*privateKey),
			Passphrase: *passphrase,
		},
		Public: getPublicKeys(publicKeys),
	}

	in := flags.Arg(0)
	out := *outputFile

	if !agentCheckPassphrase(conf.Private) {
		if in == "" {
			panic("stdin is used for piping, can't read passphrase from it, please specify the input file path in cli arg")
		}

		conf.Private.Passphrase = readPassphrase()
	}

	pubKeyMeta := PublicKeyMeta{
		Sender:    *addPublicKey,
		Receivers: publicKeys,
	}

	agentWhisper(*decryptMode, pubKeyMeta, conf, in, out)
}
