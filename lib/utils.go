package whisper

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ysmood/whisper/lib/piper"
	"github.com/ysmood/whisper/lib/secure"
)

func (w *Whisper) Handle(input io.ReadCloser, output io.WriteCloser) error {
	defer func() { _ = input.Close() }()
	defer func() { _ = output.Close() }()

	if w.conf.IsDecryption() {
		dec, err := w.Decoder(input)
		if err != nil {
			return fmt.Errorf("failed to create decoder: %w", err)
		}

		_, err = io.Copy(output, dec)
		return err
	}

	enc, err := w.Encoder(output)
	if err != nil {
		return fmt.Errorf("failed to create encoder: %w", err)
	}

	_, err = io.Copy(enc, input)
	if err != nil {
		return fmt.Errorf("failed to copy data to encoder: %w", err)
	}

	return enc.Close()
}

var ErrPrvKeyNotFound = errors.New("private key not found")

// FindSSHPrivateKey find the private key that matches the recipients' public key in the ~/.ssh folder.
func (m Meta) FindSSHPrivateKey() (string, error) {
	dir, err := SSHDir()
	if err != nil {
		return "", fmt.Errorf("failed to get SSH directory: %w", err)
	}

	pubKeys, err := filepath.Glob(dir + "/*.pub")
	if err != nil {
		return "", fmt.Errorf("failed to glob SSH public keys: %w", err)
	}

	for _, p := range pubKeys {
		b, err := ReadKey(p)
		if err != nil {
			return "", fmt.Errorf("failed to read public key %s: %w", p, err)
		}

		has, err := m.HasPubKey(PublicKey{Data: b})
		if err != nil {
			return "", fmt.Errorf("failed to check if meta has public key: %w", err)
		}

		if has {
			return strings.TrimSuffix(p, secure.PUB_KEY_EXT), nil
		}
	}

	return "", ErrPrvKeyNotFound
}

// PeakMeta read the meta data from the input stream, and return the unread input stream.
func PeakMeta(in io.ReadCloser) (*Meta, io.ReadCloser, error) {
	read := bytes.NewBuffer(nil)
	tee := io.TeeReader(in, read)
	in = &piper.WrapReadCloser{Reader: io.MultiReader(read, in), Closer: in}

	meta, err := DecodeMeta(tee)
	return meta, in, err
}

func SSHDir() (string, error) {
	p, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	return filepath.Join(p, ".ssh"), nil
}

func ReadKey(unixPath string) ([]byte, error) {
	if runtime.GOOS == "windows" {
		unixPath = filepath.FromSlash(unixPath)
	}

	b, err := os.ReadFile(unixPath)
	if err != nil {
		return nil, fmt.Errorf("%w can't read the key: %s", err, unixPath)
	}
	return b, nil
}

func IsPassphraseRight(prv PrivateKey) (bool, error) {
	_, err := secure.SSHPrvKey(prv.Data, prv.Passphrase)
	if err != nil {
		if secure.IsAuthErr(err) {
			return false, nil
		}

		return false, fmt.Errorf("failed to parse private key: %w", err)
	}

	return true, nil
}

func EncodeString(data string, conf Config) (string, error) {
	bin, err := Encode([]byte(data), conf)
	return base64.StdEncoding.EncodeToString(bin), err
}

func DecodeString(data string, conf Config) (string, error) {
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 string: %w", err)
	}

	bin, err := Decode(b, conf)
	return string(bin), err
}

func Encode(data []byte, conf Config) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	wp := New(conf)

	w, err := wp.Encoder(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create encoder for data: %w", err)
	}

	_, err = w.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write data to encoder: %w", err)
	}

	err = w.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close encoder: %w", err)
	}

	return buf.Bytes(), nil
}

func Decode(data []byte, conf Config) ([]byte, error) {
	wp := New(conf)

	r, err := wp.Decoder(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create decoder for data: %w", err)
	}

	bin, err := io.ReadAll(r)
	if err != nil && !errors.Is(err, io.EOF) {
		return bin, fmt.Errorf("failed to read decoded data: %w", err)
	}

	err = r.Close()
	if err != nil {
		return bin, fmt.Errorf("failed to close decoder: %w", err)
	}

	return bin, nil
}

func encode(data any) (res []byte, err error) {
	return json.Marshal(data)
}

func decode[T any](data []byte) (res T, err error) {
	return res, json.Unmarshal(data, &res)
}

func selectPublicKeys(keys []PublicKey) ([][]byte, error) {
	res := make([][]byte, len(keys))
	for i, key := range keys {
		data, err := key.Select()
		if err != nil {
			return nil, fmt.Errorf("failed to select public key at index %d: %w", i, err)
		}
		res[i] = data
	}
	return res, nil
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

// FetchPublicKey from github id or a remote url.
func FetchPublicKey(location string) (*PublicKey, error) {
	meta := NewPublicKeyMeta(location)
	key, err := getRemotePublicKey(meta.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch remote public key for %s: %w", location, err)
	}

	return &PublicKey{Data: key, Meta: meta}, nil
}

func getRemotePublicKey(p string) ([]byte, error) {
	u := toPublicKeyURL(p)

	res, err := http.Get(u)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key from %s: %w", u, err)
	}
	defer func() { _ = res.Body.Close() }()

	key, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key response from %s: %w", u, err)
	}

	return key, nil
}

func toPublicKeyURL(p string) string {
	if strings.HasPrefix(p, "https://") {
		return p
	}

	return fmt.Sprintf("https://github.com/%s.keys", p)
}
