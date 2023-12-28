package whisper

import (
	"compress/gzip"
	"crypto/sha1"
	"errors"
	"io"

	"github.com/ysmood/byframe/v4"
	"github.com/ysmood/whisper/lib/secure"
)

const Version = byte(1)

type MetaFlag byte

const (
	MetaGzip MetaFlag = 1 << iota
	MetaSign
	MetaLongPubKeyHash // If set, the hash size will be [sha1.Size], or it will be 4 bytes
)

// The meta format is:
//
//	[version][flags][sender][key num][key2 hash]...
//
// "version" is the whisper file format version.
// "flags" about the encoding, such as if gzip, base64 are enabled or not.
// "sender" is the sender's public key [PublicKey.ID] and [PublicKey.Selector].
// "key num" is the num of recipients.
// "key1 hash" is the hash of the first recipient's public key.
// "key2 hash" is the hash of the second recipient's public key.
// ...
func (c Config) EncodeMeta(out io.Writer) error {
	long, keyHashList, err := c.PubKeyHashList()
	if err != nil {
		return err
	}

	buf := []byte{
		// version
		Version,
		// flags
		c.genFlags(long),
	}

	// sender
	if c.Sign != nil {
		buf = append(buf, byframe.Encode([]byte(c.Sign.Meta()))...)
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

	Sender         *PublicKey
	PubKeyHashList map[string]int
}

func DecodeMeta(in io.Reader) (*Meta, error) { //nolint: funlen
	meta := Meta{PubKeyHashList: map[string]int{}}
	scanner := byframe.NewScanner(in)
	oneByte := make([]byte, 1)

	// version
	{
		_, err := io.ReadFull(in, oneByte)
		if err != nil {
			return nil, err
		}

		version := oneByte[0]

		if version != Version {
			return nil, ErrVersionMismatch
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

		key := PublicKeyFromMeta(string(sender))
		meta.Sender = &key
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

			meta.PubKeyHashList[string(key)] = i
		}
	}

	return &meta, nil
}

func (m Meta) HashSize() int {
	if m.LongPubKeyHash {
		return sha1.Size
	}

	return 4
}

// GetIndex returns the index of the encrypted secret that the p can decrypt.
func (m Meta) GetIndex(p PrivateKey) (int, error) {
	key, err := secure.SSHPrvKey(p.Data, p.Passphrase)
	if err != nil {
		return 0, err
	}

	h := secure.PublicKeyHashByPrivateKey(key)[:m.HashSize()]
	if i, has := m.PubKeyHashList[string(h)]; has {
		return i, nil
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

	h := secure.PublicKeyHash(pub)[:m.HashSize()]

	_, has := m.PubKeyHashList[string(h)]
	return has, nil
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

func (c Config) PubKeyHashList() (bool, [][]byte, error) {
	hashList := [][]byte{}
	shortList := map[string]struct{}{}
	const size = 4
	long := false

	for _, pubKey := range c.Public {
		pub, err := secure.SSHPubKey(pubKey.Data)
		if err != nil {
			return false, nil, err
		}

		h := secure.PublicKeyHash(pub)

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

	return long, hashList, nil
}
