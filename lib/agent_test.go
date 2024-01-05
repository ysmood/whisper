package whisper_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/ysmood/got"
	whisper "github.com/ysmood/whisper/lib"
	"github.com/ysmood/whisper/lib/secure"
)

func TestAgentVersionMatch(t *testing.T) {
	g := got.T(t)

	s := whisper.NewAgentServer()

	l, err := net.Listen("tcp", ":0")
	g.E(err)
	addr := l.Addr().String()

	go s.Listen(l)

	r, err := whisper.NewAgentClient(addr).IsAgentRunning(whisper.APIVersion)
	g.E(err)
	g.True(r)
}

func TestAgentVersionMismatch(t *testing.T) {
	g := got.T(t)

	s := whisper.NewAgentServer()
	s.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	l, err := net.Listen("tcp", ":0")
	g.E(err)
	addr := l.Addr().String()

	go s.Listen(l)

	r, err := whisper.NewAgentClient(addr).IsAgentRunning("v0.0.0")
	g.E(err)
	g.False(r)

	g.Err(l.Accept())
}

func TestAgentEncodeDecode(t *testing.T) {
	g := got.T(t)

	s := whisper.NewAgentServer()

	l, err := net.Listen("tcp", ":0")
	g.E(err)
	addr := l.Addr().String()

	go s.Listen(l)

	prv, pub := keyPair("id_ecdsa", "test")
	signPrv, signPub := keyPair("id_ed25519_01", "test")

	conf := whisper.Config{
		GzipLevel: gzip.DefaultCompression,
		Private:   &signPrv,
		Sign:      &signPub,
		Public:    []whisper.PublicKey{pub},
	}

	in := bytes.NewBufferString("hello")
	encoded := bytes.NewBuffer(nil)

	err = whisper.NewAgentClient(addr).CallAgent(whisper.AgentReq{
		Config: conf,
	}, in, encoded)
	g.E(err)

	conf = whisper.Config{
		GzipLevel: gzip.DefaultCompression,
		Private:   &prv,
		Sign:      &signPub,
	}

	decoded := bytes.NewBuffer(nil)
	err = whisper.NewAgentClient(addr).CallAgent(whisper.AgentReq{
		Decrypt: true,
		Config:  conf,
	}, encoded, decoded)
	g.E(err)

	g.Eq(decoded.String(), "hello")
}

func TestAgentSignVerifyErr(t *testing.T) {
	g := got.T(t)

	s := whisper.NewAgentServer()

	l, err := net.Listen("tcp", ":0")
	g.E(err)
	addr := l.Addr().String()

	go s.Listen(l)

	prv, pub := keyPair("id_ecdsa", "test")
	signPrv, signPub := keyPair("id_ed25519_01", "test")

	conf := whisper.Config{
		Private: &signPrv,
		Sign:    &signPub,
		Public:  []whisper.PublicKey{pub},
	}

	in := bytes.NewBufferString("hello")
	encoded := bytes.NewBuffer(nil)

	err = whisper.NewAgentClient(addr).CallAgent(whisper.AgentReq{
		Config: conf,
	}, in, encoded)
	g.E(err)

	conf = whisper.Config{
		Private: &prv,
	}

	decoded := bytes.NewBuffer(nil)
	err = whisper.NewAgentClient(addr).CallAgent(whisper.AgentReq{
		Decrypt: true,
		Config:  conf,
	}, encoded, decoded)
	g.Is(err, secure.ErrSignNotMatch)

	g.Eq(decoded.String(), "hello")
}

func TestAgentPassphrase(t *testing.T) {
	g := got.T(t)

	s := whisper.NewAgentServer()

	l, err := net.Listen("tcp", ":0")
	g.E(err)
	addr := l.Addr().String()

	go s.Listen(l)

	prv, _ := keyPair("id_ecdsa", "")

	// no passphrase
	r, err := whisper.NewAgentClient(addr).IsPassphraseRight(whisper.PrivateKey{})
	g.E(err)
	g.False(r)

	// right passphrase
	prv.Passphrase = "test"
	r, err = whisper.NewAgentClient(addr).IsPassphraseRight(prv)
	g.E(err)
	g.True(r)

	// cache passphrase
	prv.Passphrase = ""
	r, err = whisper.NewAgentClient(addr).IsPassphraseRight(prv)
	g.E(err)
	g.True(r)

	// wrong passphrase
	prv.Passphrase = "123"
	r, err = whisper.NewAgentClient(addr).IsPassphraseRight(prv)
	g.E(err)
	g.False(r)
}
