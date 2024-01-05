package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
)

func cacheClear() {
	// Remove the cache directory
	err := os.RemoveAll(cacheDir())
	if err != nil {
		exit(err)
	}

	err = agent().ClearCache()
	if err != nil {
		exit(err)
	}
}

func cacheDir() string {
	return filepath.Join(os.TempDir(), "whisper")
}

func cacheFilePath(key string) string {
	return filepath.Join(cacheDir(), hex.EncodeToString([]byte(key)))
}

func cache(key string, data []byte) {
	// Ensure the cache directory exists
	err := os.MkdirAll(cacheDir(), 0o755)
	if err != nil {
		exit(err)
	}

	// Write the data to the cache file
	err = os.WriteFile(cacheFilePath(key), data, 0o644)
	if err != nil {
		exit(err)
	}
}

func getCache(key string) string {
	p := cacheFilePath(key)
	if _, err := os.Stat(p); err != nil {
		return ""
	}

	return p
}
