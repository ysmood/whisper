package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	whisper "github.com/ysmood/whisper/lib"
	"github.com/ysmood/whisper/lib/piper"
)

func main() { //nolint: funlen
	flags := flag.NewFlagSet("whisper", flag.ExitOnError)

	version := flags.Bool("v", false, "Print version.")

	clearCache := flags.Bool("clear-cache", false, "Clear the cache.")

	agent := flags.Bool(AGENT_FLAG, false,
		"Run as agent, you can use env var WHISPER_AGENT_ADDR to specify the host and port to listen on.")

	privateKey := flags.String("p", WHISPER_DEFAULT_KEY, "Private key path to decrypt data.\n"+
		"You can use env var WHISPER_DEFAULT_KEY to set the default key path.\n"+
		"If it's empty a key in ~/.ssh will be auto selected.\n"+
		"If it requires a passphrase, env var WHISPER_PASSPHRASE will be used or a password cli prompt will show up.\n"+
		"The file path should always use / as the separator, even on Windows.")

	signPublicKey := flags.String("s", "",
		`To sign or verify the data this flag is required. Format is same as -e flag.`)

	var publicKeys publicKeysFlag
	flags.Var(&publicKeys, "e",
		`Encrypt with the public key, each can be a local file path, "@{GITHUB_ID}", or "@{HTTPS_URL}".`+"\n"+
			"The file path should always use / as the separator, even on Windows.")

	enableBase64 := flags.Bool("b", false, "Encoding or decoding data as base64 string.")

	compressLevel := flags.Int("c", gzip.NoCompression, "Gzip compression level.")

	inputFile := flags.String("i", "", "Input encryption/decryption from the specified file.")
	outputFile := flags.String("o", "", "Output encryption/decryption to the specified file.")

	flags.Usage = func() {
		fmt.Println("Usage: whisper [options] [input file]")
		flags.PrintDefaults()
	}

	err := flags.Parse(os.Args[1:])
	if err != nil {
		exit(err)
	}

	if *version {
		fmt.Println(whisper.APIVersion)
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

	decrypt := len(publicKeys) == 0

	input := getInput(*inputFile, flags.Arg(0))
	output := getOutput(*outputFile)

	if *enableBase64 {
		input, output = wrapBase64(decrypt, input, output)
	}

	private, input := getPrivate(decrypt, *signPublicKey != "", *privateKey, input)

	conf := whisper.Config{
		GzipLevel: *compressLevel,
		Private:   private,
		Sign:      getSign(*signPublicKey),
		Public:    getPublicKeys(publicKeys),
	}

	agentWhisper(decrypt, conf, input, output)
}

func getSign(flag string) *whisper.PublicKey {
	var sign *whisper.PublicKey
	if flag != "" {
		key := getPublicKey(flag)
		sign = &key

		if p, remote := extractRemotePublicKey(flag); remote {
			meta := whisper.PublicKeyFromMeta(p)
			sign.ID = meta.ID
			sign.Selector = meta.Selector
		}
	}
	return sign
}

var ErrUnableReadPassphrase = errors.New(
	"stdin is used for piping, can't read passphrase from it, please use the -i flag for the input file",
)

func getPrivate(decrypt bool, sign bool, location string, in io.ReadCloser) (*whisper.PrivateKey, io.ReadCloser) {
	if !decrypt && !sign {
		return nil, in
	}

	if location == "" {
		if decrypt {
			location, in = findPrivateKey(in)
		} else {
			location = filepath.Join(SSH_DIR, "id_ed25519")
		}
	}

	private := whisper.PrivateKey{
		Data:       getKey(location),
		Passphrase: WHISPER_PASSPHRASE,
	}

	if !agentCheckPassphrase(private) {
		private.Passphrase = readPassphrase(fmt.Sprintf("Please enter passphrase for private key %s: ", location))
	}

	return &private, in
}

// Parse the input file meta and find out which private key to use.
// It will search the files in ~/.ssh folder.
func findPrivateKey(in io.ReadCloser) (string, io.ReadCloser) {
	read := bytes.NewBuffer(nil)
	tee := io.TeeReader(in, read)
	in = &piper.WrapReadCloser{Reader: io.MultiReader(read, in), Closer: in}

	meta, err := whisper.DecodeMeta(tee)
	if err != nil {
		exit(err)
	}

	pubKeys, err := filepath.Glob(SSH_DIR + "/*.pub")
	if err != nil {
		exit(err)
	}

	for _, p := range pubKeys {
		has, err := meta.HasPubKey(whisper.PublicKey{Data: getKey(p)})
		if err != nil {
			exit(err)
		}

		if has {
			return prvKeyName(p), in
		}
	}

	return WHISPER_DEFAULT_KEY, in
}

func getPublicKeys(paths []string) []whisper.PublicKey {
	list := []whisper.PublicKey{}
	for _, p := range paths {
		list = append(list, getPublicKey(p))
	}
	return list
}

func wrapBase64(decrypt bool, in io.ReadCloser, out io.WriteCloser) (io.ReadCloser, io.WriteCloser) {
	enc := piper.NewBase64()
	var err error

	if decrypt {
		in, err = enc.Decoder(in)
		if err != nil {
			exit(err)
		}
	} else {
		out, err = enc.Encoder(out)
		if err != nil {
			exit(err)
		}
	}

	return in, out
}
