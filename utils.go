package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/ysmood/whisper/lib/piper"
	"golang.org/x/term"
)

func getPublicKeys(paths []string) [][]byte {
	list := [][]byte{}
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

func getPublicKey(p string) []byte {
	filter := ""
	if ss := strings.Split(p, ":"); len(ss) == 2 {
		p, filter = ss[0], ss[1]
	}

	if strings.HasPrefix(p, "@") {
		p = fmt.Sprintf("https://github.com/%s.keys", p[1:])
	}

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

		return filterPublicKeys(b, filter)
	}

	return getKey(p)
}

func filterPublicKeys(b []byte, filter string) []byte {
	for _, l := range splitIntoLines(b) {
		if strings.HasPrefix(l, "ecdsa") && strings.Contains(l, filter) {
			return []byte(l)
		}
	}

	panic("public key not found with filter: " + filter)
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

func splitIntoLines(text []byte) []string {
	scanner := bufio.NewScanner(bytes.NewReader(text))
	scanner.Split(bufio.ScanLines)

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines
}
