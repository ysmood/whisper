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
)

func TestAgentVersionMatch(t *testing.T) {
	g := got.T(t)

	s := whisper.NewAgentServer()

	l, err := net.Listen("tcp", ":0")
	g.E(err)
	addr := l.Addr().String()

	go s.Listen(l)

	g.True(whisper.IsAgentRunning(addr, whisper.Version()))
}

func TestAgentVersionMismatch(t *testing.T) {
	g := got.T(t)

	s := whisper.NewAgentServer()
	s.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	l, err := net.Listen("tcp", ":0")
	g.E(err)
	addr := l.Addr().String()

	go s.Listen(l)

	g.False(whisper.IsAgentRunning(addr, "123"))

	g.Err(l.Accept())
}

func TestAgentEncode(t *testing.T) {
	g := got.T(t)

	s := whisper.NewAgentServer()

	l, err := net.Listen("tcp", ":0")
	g.E(err)
	addr := l.Addr().String()

	go s.Listen(l)

	prv, pub := whisper.PrivateKey{read("id_ecdsa"), "test"}, read("id_ecdsa.pub")

	conf := whisper.Config{
		GzipLevel: gzip.DefaultCompression,
		Base64:    true,
		Private:   prv,
		Public:    [][]byte{pub},
	}

	in := bytes.NewBufferString("hello")
	encoded := bytes.NewBuffer(nil)

	whisper.CallAgent(addr, whisper.AgentReq{
		Decrypt: false,
		Config:  conf,
	}, in, encoded)

	str, err := whisper.DecodeString(encoded.String(), prv, pub)
	g.E(err)
	g.Eq(str, "hello")
}

func TestAgentDecode(t *testing.T) { //nolint:funlen
	g := got.T(t)

	s := whisper.NewAgentServer()

	l, err := net.Listen("tcp", ":0")
	g.E(err)
	addr := l.Addr().String()

	go s.Listen(l)

	prv, pub := whisper.PrivateKey{read("id_ecdsa"), ""}, read("id_ecdsa.pub")

	conf := whisper.Config{
		GzipLevel: gzip.DefaultCompression,
		Base64:    true,
		Private:   prv,
		Public:    [][]byte{pub},
	}

	encoded := []byte("AQDCRtKH43W_QilOxCmrm5Ew_jv7UKDyyaNc8558QKgFydkAIRiurj1K2SvvH-LKhA")

	{ // no passphrase
		decoded := bytes.NewBuffer(nil)

		g.False(whisper.CallAgent(addr, whisper.AgentReq{
			Decrypt: true,
			Config:  conf,
		}, bytes.NewReader(encoded), decoded))
	}

	{
		conf.Private.Passphrase = "test"
		decoded := bytes.NewBuffer(nil)

		g.True(whisper.CallAgent(addr, whisper.AgentReq{
			Decrypt: true,
			Config:  conf,
		}, bytes.NewReader(encoded), decoded))

		g.Eq(decoded.String(), "hello")
	}

	{ // cache passphrase
		conf.Private.Passphrase = ""
		decoded := bytes.NewBuffer(nil)

		g.True(whisper.CallAgent(addr, whisper.AgentReq{
			Decrypt: true,
			Config:  conf,
		}, bytes.NewReader(encoded), decoded))

		g.Eq(decoded.String(), "hello")
	}

	{ // wrong passphrase
		conf.Private.Passphrase = "123"
		decoded := bytes.NewBuffer(nil)

		g.False(whisper.CallAgent(addr, whisper.AgentReq{
			Decrypt: true,
			Config:  conf,
		}, bytes.NewReader(encoded), decoded))
	}
}
