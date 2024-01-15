package main

import (
	"compress/gzip"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	whisper "github.com/ysmood/whisper/lib"
	"github.com/ysmood/whisper/lib/piper"
	"github.com/ysmood/whisper/lib/secure"
)

func main() { //nolint: funlen,gocyclo,cyclop
	flags := flag.NewFlagSet("whisper", flag.ExitOnError)

	flags.Usage = func() {
		fmt.Print(USAGE)
		flags.PrintDefaults()
	}

	version := flags.Bool("v", false, "Print version.")

	clearCache := flags.Bool("clear-cache", false, "Clear the cache.")

	launchAgent := flags.Bool("agent", false, "Launch the background agent server if it's not running.")

	asAgentServer := flags.Bool(AS_AGENT_FLAG, false,
		"Run as agent server, you can use env var WHISPER_AGENT_ADDR to specify the host and port to listen on.\n"+
			"If WHISPER_AGENT_ADDR is not set, "+WHISPER_AGENT_ADDR_DEFAULT+" will be used.")

	addPassphrase := flags.String("add", "", "Add the key's passphrase to the agent cache.\n"+
		"It will also launch the agent server like -agent flag")

	if WHISPER_AGENT_ADDR == "" {
		WHISPER_AGENT_ADDR = WHISPER_AGENT_ADDR_DEFAULT
	}

	privateKey := flags.String("p", WHISPER_DEFAULT_KEY_PATH, "Private key path to decrypt data.\n"+
		"Use env var WHISPER_DEFAULT_KEY to set the default key data.\n"+
		"Use env var WHISPER_DEFAULT_KEY_PATH to set the default key path.\n"+
		"If it's empty a key in ~/.ssh will be auto selected.\n"+
		"If it requires a passphrase, env var WHISPER_PASSPHRASE will be used or a password cli prompt will show up.\n"+
		"The file path should always use / as the separator, even on Windows.")

	signPublicKey := flags.String("s", "",
		`To sign or verify the data this flag is required. Format is same as -e flag.`)

	printMeta := flags.Bool("m", false, "Print the meta data of the encrypted file.\n"+
		"Usually it's used to view the sender to avoid MITM attack.")

	var publicKeys publicKeysFlag
	flags.Var(&publicKeys, "e",
		`Encrypt with the public key, each can be a local file path, "@{GITHUB_ID}", or "@{HTTPS_URL}".`+"\n"+
			"The file path should always use / as the separator, even on Windows.")

	enableBase64 := flags.Bool("b", false, "Encoding or decoding data as base64 string.")

	compressLevel := flags.Int("c", gzip.NoCompression, "Gzip compression level.")

	inputFile := flags.String("i", "", "Input encryption/decryption from the specified file or https url.")
	outputFile := flags.String("o", "", "Output encryption/decryption to the specified file.")

	genKeyFile := flags.String("gen-key", "", "Generate a key pair and save to the specified path.")

	batchEncrypt := flags.String("be", "", "Encrypt all files in the batch config file.")
	batchDecrypt := flags.String("bd", "", "Decrypt all files in the batch config file.")

	err := flags.Parse(os.Args[1:])
	if err != nil {
		exit(err)
	}

	if *version {
		fmt.Println(whisper.APIVersion)
		return
	}

	if *genKeyFile != "" {
		genKey(*genKeyFile)
		return
	}

	if *clearCache {
		cacheClear()
		return
	}

	if *asAgentServer {
		runAsAgentServer()
		return
	}

	if *addPassphrase != "" {
		agentAddPassphrase(*addPassphrase)
		return
	}

	if *launchAgent {
		launchAgentServer()
		return
	}

	if *batchEncrypt != "" {
		runBatch(false, *batchEncrypt, "")
		return
	}

	if *batchDecrypt != "" {
		runBatch(true, *batchDecrypt, *privateKey)
		return
	}

	decrypt := len(publicKeys) == 0

	input := getInput(*inputFile, flags.Arg(0))
	output := getOutput(*outputFile)

	if *enableBase64 {
		if decrypt {
			input = &piper.WrapReadCloser{Reader: base64.NewDecoder(base64.StdEncoding, input), Closer: input}
		} else {
			output = base64.NewEncoder(base64.StdEncoding, output)
		}
	}

	var meta *whisper.Meta
	if decrypt {
		meta, input = getMeta(input)
	}

	if *printMeta {
		fmt.Println(meta.String())
		return
	}

	private := getPrivate(decrypt, *signPublicKey != "", *privateKey, meta)

	conf := whisper.Config{
		GzipLevel: *compressLevel,
		Private:   private,
		Sign:      getSign(*signPublicKey),
		Public:    getPublicKeys(publicKeys),
	}

	err = run(conf, input, output)
	if err != nil {
		exit(err)
	}
}

func run(conf whisper.Config, input io.ReadCloser, output io.WriteCloser) error {
	if isAgentServerRunning() {
		return agentWhisper(conf, input, output)
	}

	return whisper.New(conf).Handle(input, output)
}

func getMeta(input io.ReadCloser) (*whisper.Meta, io.ReadCloser) {
	meta, input, err := whisper.PeakMeta(input)
	if err != nil {
		if isBase64(input) {
			exit(fmt.Errorf("the input is base64 encoded, you might want to add -b flag to decrypt: %w", err))
		}

		exit(err)
	}

	return meta, input
}

func getSign(path string) *whisper.PublicKey {
	var sign *whisper.PublicKey
	if path != "" {
		key := fetchPublicKey(path)
		sign = &key
	}
	return sign
}

var ErrUnableReadPassphrase = errors.New(
	"stdin is used for piping, can't read passphrase from it, please use the -i flag for the input file",
)

func getPrivate(decrypt bool, sign bool, location string, meta *whisper.Meta) *whisper.PrivateKey {
	if !decrypt && !sign {
		return nil
	}

	if location == "" && WHISPER_DEFAULT_KEY != "" {
		private := whisper.PrivateKey{
			Data:       []byte(WHISPER_DEFAULT_KEY),
			Passphrase: WHISPER_PASSPHRASE,
		}

		return ensurePassphrase(private, location)
	}

	if location == "" && decrypt {
		location = findPrivateKey(meta)
	}

	if location == "" {
		dir, err := whisper.SSHDir()
		if err != nil {
			exit(err)
		}

		location = filepath.Join(dir, "id_ed25519")
	}

	key, err := whisper.ReadKey(location)
	if err != nil {
		exit(err)
	}

	private := whisper.PrivateKey{
		Data:       key,
		Passphrase: WHISPER_PASSPHRASE,
	}

	return ensurePassphrase(private, location)
}

func ensurePassphrase(private whisper.PrivateKey, location string) *whisper.PrivateKey {
	if isAgentServerRunning() {
		if !agentCheckPassphrase(private) {
			private.Passphrase = getPassphrase(location)
		}
	} else {
		right, err := whisper.IsPassphraseRight(private)
		if err != nil {
			exit(err)
		}

		if !right {
			private.Passphrase = getPassphrase(location)
		}
	}

	return &private
}

// Parse the input file meta and find out which private key to use.
// It will search the files in ~/.ssh folder.
func findPrivateKey(meta *whisper.Meta) string {
	p, err := meta.FindSSHPrivateKey()
	if err == nil {
		return p
	}

	return WHISPER_DEFAULT_KEY_PATH
}

func getPublicKeys(paths []string) []whisper.PublicKey {
	list := []whisper.PublicKey{}
	for _, p := range paths {
		list = append(list, fetchPublicKey(p))
	}
	return list
}

func fetchPublicKey(location string) whisper.PublicKey {
	var remote bool
	location, remote = extractRemotePublicKey(location)

	if remote {
		key := &whisper.PublicKey{}
		if has := getCache(location, key); has {
			return *key
		}

		key, err := whisper.FetchPublicKey(location)
		if err != nil {
			exit(fmt.Errorf("failed to fetch public key: %w", err))
		}

		cache(location, key)

		return *key
	}

	b, err := whisper.ReadKey(location)
	if err != nil {
		exit(err)
	}

	return whisper.PublicKey{Data: b}
}

var errPrvKeyExists = fmt.Errorf("private key already exists")

func genKey(path string) {
	if _, err := os.Stat(path); err == nil {
		exit(fmt.Errorf("%w: you have to remove it first", errPrvKeyExists))
	}

	pass := readPassphrase("Enter passphrase (empty for no passphrase): ")
	if pass != "" {
		for {
			p := readPassphrase("Enter same passphrase again: ")
			if pass == p {
				break
			}
			fmt.Fprintln(os.Stderr, "Passphrases didn't match, try again.")
		}
	}

	comment := readLine("Enter the comment for it: ")
	deterministic := readLine("Enter yes for deterministic key: ") == "yes"

	err := secure.GenerateKeyFile(deterministic, path, comment, pass)
	if err != nil {
		exit(err)
	}
}

func extractRemotePublicKey(p string) (string, bool) {
	if strings.HasPrefix(p, "@") {
		return p[1:], true
	}

	return p, false
}

func runBatch(decrypt bool, path string, privateKey string) {
	b, err := NewBatch(path)
	if err != nil {
		exit(err)
	}

	if decrypt {
		err = b.Decrypt(privateKey)
	} else {
		err = b.Encrypt()
	}
	if err != nil {
		exit(err)
	}
}
