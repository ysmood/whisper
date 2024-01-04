package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	whisper "github.com/ysmood/whisper/lib"
	"github.com/ysmood/whisper/lib/piper"
	"golang.org/x/term"
)

func exit(err error) {
	fmt.Fprintln(os.Stderr, "Error:", err.Error())
	os.Exit(1)
}

func getKey(keyFile string) []byte {
	if runtime.GOOS == "windows" {
		keyFile = filepath.FromSlash(keyFile)
	}

	b, err := os.ReadFile(keyFile)
	if err != nil {
		exit(err)
	}
	return b
}

func readPassphrase(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)

	fd := int(os.Stdin.Fd())

	if !term.IsTerminal(fd) {
		exit(ErrUnableReadPassphrase)
	}

	inputPass, err := term.ReadPassword(fd)
	if err != nil {
		exit(err)
	}

	fmt.Fprintln(os.Stderr)

	return string(inputPass)
}

func getInput(path, defaultPath string) io.ReadCloser {
	if path == "" {
		path = defaultPath
	}

	if path == "" {
		return os.Stdin
	}

	f, err := os.Open(path)
	if err != nil {
		exit(err)
	}

	return f
}

func getOutput(file string) io.WriteCloser {
	if file == "" {
		return piper.NopCloser(os.Stdout)
	}

	err := os.MkdirAll(filepath.Dir(file), 0o700)
	if err != nil {
		exit(err)
	}

	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		exit(err)
	}
	return f
}

func extractRemotePublicKey(p string) (string, bool) {
	if strings.HasPrefix(p, "@") {
		return p[1:], true
	}

	return p, false
}

func extractPublicKeySelector(p string) (string, string) {
	sel := whisper.PublicKeyFromMeta(strings.TrimPrefix(p, "https://")).Selector
	if sel == "" {
		return p, ""
	}
	return p[:len(p)-len(sel)-1], sel
}

func toPublicKeyURL(p string) string {
	if strings.HasPrefix(p, "https://") {
		return p
	}

	return fmt.Sprintf("https://github.com/%s.keys", p)
}

func getPublicKey(p string) whisper.PublicKey {
	p, remote := extractRemotePublicKey(p)
	p, sel := extractPublicKeySelector(p)

	var key []byte
	if remote {
		key = getRemotePublicKey(p)
	} else {
		key = getKey(p)
	}

	if len(key) == 0 {
		exit(fmt.Errorf("%w: %s", whisper.ErrPubKeyNotFound, p))
	}

	return whisper.PublicKey{Data: key, ID: p, Selector: sel}
}

func getRemotePublicKey(p string) []byte {
	u := toPublicKeyURL(p)

	if b, has := getCache(u); has {
		return b
	}

	res, err := http.Get(u) //nolint:noctx
	if err != nil {
		exit(err)
	}
	defer func() { _ = res.Body.Close() }()

	key, err := io.ReadAll(res.Body)
	if err != nil {
		exit(err)
	}

	cache(u, key)

	return key
}

func prvKeyName(pub string) string {
	return strings.TrimSuffix(pub, ".pub")
}

type publicKeysFlag []string

func (i *publicKeysFlag) String() string {
	return strings.Join(*i, ", ")
}

func (i *publicKeysFlag) Set(value string) error {
	*i = append(*i, value)
	return nil
}
