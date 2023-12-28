package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/ysmood/whisper/lib/secure"
)

func main() {
	dir := filepath.FromSlash("lib/secure/shared-keys")

	err := os.MkdirAll(dir, 0o755)
	if err != nil {
		panic(err)
	}

	for _, info := range secure.SupportedKeyTypes {
		for _, bitSize := range info.BitSize {
			f := filepath.Join(dir, "id_"+info.Type+"_"+strconv.Itoa(bitSize))

			cmd := exec.Command("ssh-keygen", "-t", info.Type, "-b", strconv.Itoa(bitSize), "-N", "", "-f", f)
			cmd.Stderr = os.Stderr
			cmd.Stdout = os.Stdout

			err := cmd.Run()
			if err != nil {
				panic(err)
			}
		}
	}
}
