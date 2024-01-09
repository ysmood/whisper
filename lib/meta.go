package whisper

import (
	"compress/gzip"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ysmood/byframe/v4"
	"github.com/ysmood/whisper/lib/secure"
)

type MetaFlag byte

const (
	MetaGzip MetaFlag = 1 << iota
	MetaSign
	MetaLongPubKeyHash // If set, the hash size will be [sha1.Size], or it will be 4 bytes
)

// The meta format is:
//
//	[version][flags][signer][key num][keyInfo1][keyInfo2]...
//
// "version" is the whisper file format version.
// "flags" about the encoding, such as if gzip, base64 are enabled or not.
// "signer" is the signer's public key [PublicKey.ID] and [PublicKey.Selector].
// "key num" is the num of recipients.
// "keyInfo1" is the first recipient's public key info.
// "keyInfo2" is the second recipient's public key info.
// ...
// The key info format is: [public key hash][public key meta].
func (c Config) EncodeMeta(out io.Writer) error {
	long, keyHashList, err := c.Recipients()
	if err != nil {
		return err
	}

	buf := []byte{
		// version
		WireFormatVersion,
		// flags
		c.genFlags(long),
	}

	// sender
	if c.Sign != nil {
		buf = append(buf, byframe.Encode([]byte(c.Sign.Meta.String()))...)
	}

	// key num
	buf = append(buf, byframe.Encode(byframe.EncodeHeader(len(keyHashList)))...)

	// key list
	for _, h := range keyHashList {
		buf = append(buf, h...)
	}

	_, err = out.Write(buf)
	return err
}

var ErrVersionMismatch = errors.New("whisper file format version mismatch")

type Meta struct {
	Gzip           bool
	Sign           bool
	LongPubKeyHash bool

	Sender *PublicKeyMeta

	// The key is the hash of the recipient's public key, value is the index of the recipient in the key list.
	Recipients map[string]Recipient
}

type Recipient struct {
	Index int
	Meta  PublicKeyMeta
}

// DecodeMeta decodes the meta from the whisper file.
func DecodeMeta(in io.Reader) (*Meta, error) {
	meta := Meta{Recipients: map[string]Recipient{}}
	scanner := byframe.NewScanner(in)
	oneByte := make([]byte, 1)

	// version
	{
		_, err := io.ReadFull(in, oneByte)
		if err != nil {
			return nil, err
		}

		version := oneByte[0]

		if version != WireFormatVersion {
			return nil, fmt.Errorf(
				"%w: expect v%d but got v%d",
				ErrVersionMismatch,
				WireFormatVersion,
				version,
			)
		}
	}

	// flags
	{
		_, err := io.ReadFull(in, oneByte)
		if err != nil {
			return nil, err
		}

		flags := MetaFlag(oneByte[0])

		meta.Gzip = flags&MetaGzip != 0
		meta.Sign = flags&MetaSign != 0
		meta.LongPubKeyHash = flags&MetaLongPubKeyHash != 0
	}

	// sender
	if meta.Sign {
		sender, err := scanner.Next()
		if err != nil {
			return nil, err
		}

		keyMeta := NewPublicKeyMeta(string(sender))
		meta.Sender = &keyMeta
	}

	// key list
	{
		numRaw, err := scanner.Next()
		if err != nil {
			return nil, err
		}

		// key num
		_, num := byframe.DecodeHeader(numRaw)

		for i := 0; i < num; i++ {
			key := make([]byte, meta.HashSize())

			_, err = io.ReadFull(in, key)
			if err != nil {
				return nil, err
			}

			b, err := scanner.Next()
			if err != nil {
				return nil, err
			}

			keyMeta := NewPublicKeyMeta(string(b))

			meta.Recipients[string(key)] = Recipient{Index: i, Meta: keyMeta}
		}
	}

	return &meta, nil
}

func (m Meta) HashSize() int {
	if m.LongPubKeyHash {
		return secure.KEY_HASH_SIZE
	}

	return 4
}

// GetIndex returns the index of the encrypted secret that the p can decrypt.
func (m Meta) GetIndex(p PrivateKey) (int, error) {
	key, err := secure.SSHPrvKey(p.Data, p.Passphrase)
	if err != nil {
		return 0, err
	}

	h, err := secure.PublicKeyHashByPrivateKey(key)
	if err != nil {
		return 0, err
	}

	if r, has := m.Recipients[string(h[:m.HashSize()])]; has {
		return r.Index, nil
	}

	return 0, secure.ErrNotRecipient
}

func (m Meta) HasPubKey(p PublicKey) (bool, error) {
	b, err := p.Select()
	if err != nil {
		return false, err
	}

	pub, err := secure.SSHPubKey(b)
	if err != nil {
		return false, err
	}

	h, err := secure.PublicKeyHash(pub)
	if err != nil {
		return false, err
	}

	_, has := m.Recipients[string(h[:m.HashSize()])]
	return has, nil
}

func (m Meta) String() string {
	recipients := make([]string, len(m.Recipients))
	for hash, r := range m.Recipients {
		list := []string{hex.EncodeToString([]byte(hash))}
		if r.Meta.String() != "" {
			list = append([]string{r.Meta.String()}, list...)
		}
		recipients[r.Index] = strings.Join(list, ":")
	}

	sender := ""
	if m.Sender != nil {
		sender = m.Sender.String()
	}

	return fmt.Sprintf(
		"wire-format: v%d\nsign: %v\nsigner: \"%s\"\nrecipients: %v\ngzip: %v",
		WireFormatVersion,
		m.Sign,
		sender,
		recipients,
		m.Gzip,
	)
}

func (c Config) genFlags(long bool) byte {
	var flags MetaFlag

	if c.GzipLevel != gzip.NoCompression {
		flags |= MetaGzip
	}

	if c.Sign != nil {
		flags |= MetaSign
	}

	if long {
		flags |= MetaLongPubKeyHash
	}

	return byte(flags)
}

func (c Config) Recipients() (bool, [][]byte, error) {
	hashList := [][]byte{}
	shortList := map[string]struct{}{}
	const size = 4
	long := false

	for _, pubKey := range c.Public {
		pub, err := secure.SSHPubKey(pubKey.Data)
		if err != nil {
			return false, nil, err
		}

		h, err := secure.PublicKeyHash(pub)
		if err != nil {
			return false, nil, err
		}

		hashList = append(hashList, h)

		short := string(h[:size])
		if _, has := shortList[short]; has {
			long = true
		} else {
			shortList[short] = struct{}{}
		}
	}

	if !long {
		for i, h := range hashList {
			hashList[i] = h[:size]
		}
	}

	recipients := [][]byte{}
	for i, h := range hashList {
		keyMeta := byframe.Encode([]byte(c.Public[i].Meta.String()))
		recipients = append(recipients, append(h, keyMeta...))
	}

	return long, recipients, nil
}
