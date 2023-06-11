package main

import (
	"os"
	"testing"

	"github.com/ysmood/got"
)

func TestBasic(t *testing.T) {
	g := got.T(t)

	g.E(os.RemoveAll("tmp"))
	g.MkdirAll(0o755, "tmp")
	g.Chdir("tmp")

	g.WriteFile("text", "ok")

	os.Args = []string{"", "-g"}
	main()

	os.Args = []string{"", "-o", "encrypted", "text"}
	main()

	os.Args = []string{"", "-d", "-o", "decrypted", "encrypted"}
	main()

	g.Eq(g.Read("decrypted").String(), g.Read("text").String())
}
