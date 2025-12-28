package main

import (
	"bufio"
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

func getPassphrase(location string) string {
	return readPassphrase(fmt.Sprintf("Enter passphrase for private key %s: ", location))
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

func readLine(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)

	reader := bufio.NewReader(os.Stdin)

	line, err := reader.ReadString('\n')
	if err != nil {
		exit(err)
	}

	return strings.TrimSpace(line)
}

func getInput(path, defaultPath string) io.ReadCloser {
	if path == "" {
		path = defaultPath
	}

	if path == "" {
		return os.Stdin
	}

	if strings.HasPrefix(path, "https://") {
		res, err := http.Get(path)
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

	return newLazyFileWriter(file)
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

type lazyFileWriter struct {
	path string
	file *os.File
}

func (w *lazyFileWriter) Write(p []byte) (n int, err error) {
	if w.file == nil {
		w.file, err = os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return 0, fmt.Errorf("failed to open file %s: %w", w.path, err)
		}
	}
	return w.file.Write(p)
}

func (w *lazyFileWriter) Close() error {
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

func newLazyFileWriter(path string) *lazyFileWriter {
	return &lazyFileWriter{path: path}
}
