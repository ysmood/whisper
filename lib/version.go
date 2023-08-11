package whisper

import (
	"crypto/md5"
	"embed"
	"encoding/hex"
	"io/fs"
)

//go:embed *.go **/*.go
var source embed.FS

var versionCache string

// Version return the md5 hash of all the files in [source].
func Version() string {
	if versionCache != "" {
		return versionCache
	}

	hash := md5.New()

	err := fs.WalkDir(source, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		b, err := source.ReadFile(path)
		if err != nil {
			return err
		}

		_, err = hash.Write(b)
		return err
	})
	if err != nil {
		panic(err)
	}

	versionCache = hex.EncodeToString(hash.Sum(nil))

	return versionCache
}
