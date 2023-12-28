package whisper_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ysmood/got"
	whisper "github.com/ysmood/whisper/lib"
	"github.com/ysmood/whisper/lib/secure"
)

func ExampleNew() {
	recipient01, recipient01Pub := keyPair("id_ecdsa01", "test")
	recipient02, recipient02Pub := keyPair("id_ecdsa02", "test")

	// Encrypt the message that can be decrypted by both recipient01 and recipient02.
	encrypted, _ := whisper.EncodeString("hello world!", whisper.Config{
		Public: []whisper.PublicKey{recipient01Pub, recipient02Pub},
	})

	decrypted01, _ := whisper.DecodeString(encrypted, whisper.Config{Private: &recipient01})
	decrypted02, _ := whisper.DecodeString(encrypted, whisper.Config{Private: &recipient02})

	fmt.Println(decrypted01, decrypted02)

	// Output: hello world! hello world!
}

func TestBasic(t *testing.T) {
	g := got.T(t)

	recipient01, recipient01Pub := keyPair("id_ed25519_01", "test")
	recipient02, recipient02Pub := keyPair("id_ed25519_02", "")

	// Encrypt the message that can be decrypted by both recipient01 and recipient02.
	encrypted, err := whisper.EncodeString("hello world!", whisper.Config{
		Public: []whisper.PublicKey{recipient01Pub, recipient02Pub},
	})
	g.E(err)

	g.Len(encrypted, 110)

	decrypted01, err := whisper.DecodeString(encrypted, whisper.Config{Private: &recipient01})
	g.E(err)

	decrypted02, err := whisper.DecodeString(encrypted, whisper.Config{Private: &recipient02})
	g.E(err)

	g.Eq(decrypted01, "hello world!")
	g.Eq(decrypted01, decrypted02)
}

func TestSign(t *testing.T) {
	g := got.T(t)

	sender01, senderPub := keyPair("id_ecdsa01", "test")
	recipient01, recipient01Pub := keyPair("id_ed25519_01", "test")
	recipient02, recipient02Pub := keyPair("id_ed25519_02", "")

	// Encrypt the message that can be decrypted by both recipient01 and recipient02.
	encrypted, err := whisper.EncodeString("hello world!", whisper.Config{
		Private: &sender01,
		Sign:    &senderPub,
		Public:  []whisper.PublicKey{recipient01Pub, recipient02Pub},
	})
	g.E(err)

	decrypted01, err := whisper.DecodeString(encrypted, whisper.Config{
		Private: &recipient01,
		Sign:    &senderPub,
	})
	g.E(err)

	decrypted02, err := whisper.DecodeString(encrypted, whisper.Config{
		Private: &recipient02,
		Sign:    &senderPub,
	})
	g.E(err)

	g.Eq(decrypted01, "hello world!")
	g.Eq(decrypted01, decrypted02)

	decrypted02, err = whisper.DecodeString(encrypted, whisper.Config{
		Private: &recipient02,
	})
	g.Is(err, secure.ErrSignNotMatch)

	g.Eq(decrypted02, "hello world!")
}

func TestPubKeyHashList(t *testing.T) {
	g := got.T(t)

	_, recipient01Pub := keyPair("id_ecdsa01", "test")
	_, recipient02Pub := keyPair("id_ecdsa02", "test")

	conf := whisper.Config{Public: []whisper.PublicKey{recipient01Pub, recipient02Pub}}

	long, list, err := conf.PubKeyHashList()
	g.E(err)

	g.False(long)
	g.Len(list[0], 4)
	g.Snapshot("hash list", list)
}

func TestMeta(t *testing.T) {
	g := got.T(t)

	sender01, recipient01Pub := keyPair("id_ecdsa01", "test")
	sender02, recipient02Pub := keyPair("id_ecdsa02", "test")

	conf := whisper.Config{
		GzipLevel: 1,
		Private:   &sender01,
		Sign: &whisper.PublicKey{
			ID:       "test",
			Selector: "abc",
		},
		Public: []whisper.PublicKey{recipient01Pub, recipient02Pub},
	}

	buf := bytes.NewBuffer(nil)

	g.E(conf.EncodeMeta(buf))

	meta, err := whisper.DecodeMeta(buf)
	g.E(err)

	g.Snapshot("meta", meta)

	index, err := meta.GetIndex(sender02)
	g.E(err)
	g.Eq(index, 1)

	has, err := meta.HasPubKey(recipient01Pub)
	g.E(err)
	g.True(has)

	has, err = meta.HasPubKey(recipient02Pub)
	g.E(err)
	g.True(has)
}

func keyPair(privateKeyName, passphrase string) (whisper.PrivateKey, whisper.PublicKey) {
	prv, err := os.ReadFile(filepath.FromSlash("secure/test_data/" + privateKeyName))
	if err != nil {
		panic(err)
	}

	pub, err := os.ReadFile(filepath.FromSlash("secure/test_data/" + privateKeyName + ".pub"))
	if err != nil {
		panic(err)
	}

	return whisper.PrivateKey{prv, passphrase}, whisper.PublicKey{Data: pub}
}
