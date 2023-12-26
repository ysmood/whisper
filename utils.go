package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/ysmood/whisper/lib/piper"
	"github.com/ysmood/whisper/lib/secure"
	"golang.org/x/term"
)

func getPublicKeys(paths []string) []secure.KeyWithFilter {
	list := []secure.KeyWithFilter{}
	for _, p := range paths {
		list = append(list, getPublicKey(p))
	}
	return list
}

func getKey(keyFile string) []byte {
	b, err := os.ReadFile(keyFile)
	if err != nil {
		panic(err)
	}
	return b
}

func readPassphrase() string {
	fmt.Fprint(os.Stderr, "Enter passphrase for private key: ")
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
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
		return piper.NopCloser(os.Stdout)
	}

	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	return f
}

func extractRemotePublicKey(p string) (string, bool) {
	if strings.HasPrefix(p, "@") {
		return p[1:], true
	}

	return p, false
}

func extractPublicKeyFilter(p string) (string, string) {
	if ss := strings.Split(p, ":"); len(ss) == 2 {
		return ss[0], ss[1]
	}
	return p, ""
}

func toPublicKeyURL(p string) string {
	if strings.HasPrefix(p, "https://") {
		return p
	}

	return fmt.Sprintf("https://github.com/%s.keys", p)
}

func getPublicKey(p string) secure.KeyWithFilter {
	p, filter := extractPublicKeyFilter(p)

	p, remote := extractRemotePublicKey(p)

	var key []byte
	if remote {
		key = getRemotePublicKey(p)
	} else {
		key = getKey(p)
	}

	return secure.KeyWithFilter{Key: key, Filter: filter}
}

func getRemotePublicKey(p string) []byte {
	u := toPublicKeyURL(p)

	if b, has := getCache(u); has {
		return b
	}

	res, err := http.Get(u) //nolint:noctx
	if err != nil {
		panic(err)
	}
	defer func() { _ = res.Body.Close() }()

	key, err := io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	cache(u, key)

	return key
}

func pubKeyName(prv string) string {
	return prv + ".pub"
}

type publicKeysFlag []string

func (i *publicKeysFlag) String() string {
	return strings.Join(*i, ", ")
}

func (i *publicKeysFlag) Set(value string) error {
	*i = append(*i, value)
	return nil
}
