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
	if w.conf.IsDecryption() {
		dec, err := w.Decoder(input)
		if err != nil {
			return err
		}

		_, err = io.Copy(output, dec)
		return err
	}

	enc, err := w.Encoder(output)
	if err != nil {
		return err
	}

	_, err = io.Copy(enc, input)
	if err != nil {
		return err
	}

	return enc.Close()
}

var ErrPrvKeyNotFound = errors.New("private key not found")

// FindSSHPrivateKey find the private key that matches the recipients' public key in the ~/.ssh folder.
func (m *Meta) FindSSHPrivateKey() (string, error) {
	dir, err := SSHDir()
	if err != nil {
		return "", err
	}

	pubKeys, err := filepath.Glob(dir + "/*.pub")
	if err != nil {
		return "", err
	}

	for _, p := range pubKeys {
		b, err := ReadKey(p)
		if err != nil {
			return "", err
		}

		has, err := m.HasPubKey(PublicKey{Data: b})
		if err != nil {
			return "", err
		}

		if has {
			return strings.TrimSuffix(p, ".pub"), nil
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
		return "", err
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

		return false, err
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
		return "", err
	}

	bin, err := Decode(b, conf)
	return string(bin), err
}

func Encode(data []byte, conf Config) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	wp := New(conf)

	w, err := wp.Encoder(buf)
	if err != nil {
		return nil, err
	}

	_, err = w.Write(data)
	if err != nil {
		return nil, err
	}

	err = w.Close()

	return buf.Bytes(), err
}

func Decode(data []byte, conf Config) ([]byte, error) {
	wp := New(conf)

	r, err := wp.Decoder(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	bin, err := io.ReadAll(r)
	if err != nil {
		return bin, err
	}

	err = r.Close()

	return bin, err
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
			return nil, err
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

// FetchPublicKey from the location, it can be a local file path, github id or a remote url.
// Only remote file will have [PublicKey.ID] and [PublicKey.Selector].
func FetchPublicKey(location string) (*PublicKey, error) {
	location, remote := ExtractRemotePublicKey(location)
	location, sel := extractPublicKeySelector(location)

	var key []byte
	var err error
	var id, selector string
	if remote {
		key, err = getRemotePublicKey(location)
		id = location
		selector = sel
	} else {
		key, err = ReadKey(location)
	}
	if err != nil {
		return nil, err
	}

	if len(key) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrPubKeyNotFound, location)
	}

	return &PublicKey{Data: key, ID: id, Selector: selector}, nil
}

func getRemotePublicKey(p string) ([]byte, error) {
	u := toPublicKeyURL(p)

	res, err := http.Get(u) //nolint:noctx
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()

	key, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func toPublicKeyURL(p string) string {
	if strings.HasPrefix(p, "https://") {
		return p
	}

	return fmt.Sprintf("https://github.com/%s.keys", p)
}

func ExtractRemotePublicKey(p string) (string, bool) {
	if strings.HasPrefix(p, "@") {
		return p[1:], true
	}

	return p, false
}

func extractPublicKeySelector(p string) (string, string) {
	sel := PublicKeyFromMeta(strings.TrimPrefix(p, "https://")).Selector
	if sel == "" {
		return p, ""
	}
	return p[:len(p)-len(sel)-1], sel
}
