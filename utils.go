package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ysmood/whisper/lib/piper"
	"golang.org/x/term"
)

func exit(err error) {
	fmt.Fprintln(os.Stderr, "Error:", err.Error())
	os.Exit(1)
}

func readPassphrase(location string) string {
	fmt.Fprintf(os.Stderr, "Please enter passphrase for private key %s: ", location)

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

	if strings.HasPrefix(path, "https://") {
		res, err := http.Get(path) //nolint:noctx
		if err != nil {
			exit(err)
		}

		return res.Body
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

type publicKeysFlag []string

func (i *publicKeysFlag) String() string {
	return strings.Join(*i, ", ")
}

func (i *publicKeysFlag) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func isBase64(in io.Reader) bool {
	dec := base64.NewDecoder(base64.StdEncoding, in)
	buf := bytes.NewBuffer(nil)

	_, err := io.Copy(buf, dec)
	return err == nil
}
