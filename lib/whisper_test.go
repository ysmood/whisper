package whisper_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ysmood/got"
	whisper "github.com/ysmood/whisper/lib"
	"github.com/ysmood/whisper/lib/piper"
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

	data := "hello world!"

	// Encrypt the message that can be decrypted by both recipient01 and recipient02.
	encrypted, err := whisper.EncodeString(data, whisper.Config{
		Public:    []whisper.PublicKey{recipient01Pub, recipient02Pub},
		GzipLevel: 9,
	})
	g.E(err)

	g.Len(encrypted, 272)

	decrypted01, err := whisper.DecodeString(encrypted, whisper.Config{Private: &recipient01})
	g.E(err)

	decrypted02, err := whisper.DecodeString(encrypted, whisper.Config{Private: &recipient02})
	g.E(err)

	g.Eq(decrypted01, data)
	g.Eq(decrypted01, decrypted02)
}

func TestSign(t *testing.T) {
	g := got.T(t)

	sender, senderPub := keyPair("id_ecdsa01", "test")
	recipient01, recipient01Pub := keyPair("id_ed25519_01", "test")
	recipient02, recipient02Pub := keyPair("id_ed25519_02", "")

	// Encrypt the message that can be decrypted by both recipient01 and recipient02.
	encrypted, err := whisper.EncodeString("hello world!", whisper.Config{
		Private: &sender,
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
	g.Is(err, secure.ErrSignMismatch)

	g.Eq(decrypted02, "hello world!")
}

func TestWhisperHandle(t *testing.T) {
	g := got.T(t)

	recipient01, recipient01Pub := keyPair("id_ed25519_01", "test")

	data := "hello world!"
	encrypted := bytes.NewBuffer(nil)

	err := whisper.New(whisper.Config{
		Public: []whisper.PublicKey{recipient01Pub},
	}).Handle(io.NopCloser(bytes.NewReader([]byte(data))), piper.NopCloser(encrypted))
	g.E(err)

	decrypted := bytes.NewBuffer(nil)
	err = whisper.New(whisper.Config{
		Private: &recipient01,
	}).Handle(io.NopCloser(encrypted), piper.NopCloser(decrypted))
	g.E(err)

	g.Eq(decrypted.String(), data)
}

func TestPubKeyHashList(t *testing.T) {
	g := got.T(t)

	_, recipient01Pub := keyPair("id_ecdsa01", "test")
	_, recipient02Pub := keyPair("id_ecdsa02", "test")

	conf := whisper.Config{Public: []whisper.PublicKey{recipient01Pub, recipient02Pub}}

	long, list, err := conf.Recipients()
	g.E(err)

	g.False(long)
	g.Len(list[0], 5)
	g.Snapshot("hash list", list)
}

func TestPubKeyLongHashList(t *testing.T) {
	g := got.T(t)

	_, recipient01Pub := keyPair("id_ecdsa01", "test")
	_, recipient02Pub := keyPair("id_ecdsa01", "test")

	conf := whisper.Config{Public: []whisper.PublicKey{recipient01Pub, recipient02Pub}}

	long, list, err := conf.Recipients()
	g.E(err)

	g.True(long)
	g.Len(list[0], secure.KEY_HASH_SIZE+1)
	g.Snapshot("hash list", list)
}

func TestMeta(t *testing.T) {
	g := got.T(t)

	sender01, recipient01Pub := keyPair("id_ecdsa01", "test")
	sender02, recipient02Pub := keyPair("id_ecdsa02", "test")

	recipient01Pub.Meta = whisper.NewPublicKeyMeta("bot:lzdHAyN")

	conf := whisper.Config{
		GzipLevel: 1,
		Private:   &sender01,
		Sign: &whisper.PublicKey{
			Meta: whisper.PublicKeyMeta{
				ID:       "test",
				Selector: "abc",
			},
		},
		Public: []whisper.PublicKey{recipient01Pub, recipient02Pub},
	}

	buf := bytes.NewBuffer(nil)

	g.E(conf.EncodeMeta(buf))

	meta, _, err := whisper.PeakMeta(io.NopCloser(buf))
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

	g.Snapshot("meta string", meta.String())
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

func TestFetchPublicKey(t *testing.T) {
	g := got.T(t)

	{
		pub, err := whisper.FetchPublicKey("https://github.com/ysmood.keys")
		g.E(err)

		g.Has(string(pub.Data), "ed25519")
		g.Eq(pub.Meta.ID, "https://github.com/ysmood.keys")
		g.Eq(pub.Meta.Selector, "")
	}

	{
		pub, err := whisper.FetchPublicKey("ysmood:ssh")
		g.E(err)

		g.Has(string(pub.Data), "ssh")
		g.Eq(pub.Meta.ID, "ysmood")
		g.Eq(pub.Meta.Selector, "ssh")
	}
}
