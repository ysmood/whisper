package secure_test

import (
	"bytes"
	"testing"

	"github.com/ysmood/got"
	"github.com/ysmood/whisper/lib/secure"
)

func TestECDH(t *testing.T) {
	g := got.T(t)

	public, private, err := secure.GenKeys("test")
	g.E(err)

	ecc, err := secure.NewECC(public, private, "test")
	g.E(err)

	buf := bytes.NewBuffer(nil)
	enc, err := ecc.Encoder(buf)
	g.E(err)
	g.E(enc.Write([]byte("ok")))
	g.E(enc.Close())

	dec, err := ecc.Decoder(buf)
	g.E(err)

	g.Eq(g.Read(dec).String(), "ok")
}
