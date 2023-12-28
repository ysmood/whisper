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
		panic(err)
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
		panic(err)
	}

	// Write the data to the cache file
	err = os.WriteFile(cacheFilePath(key), data, 0o644)
	if err != nil {
		panic(err)
	}
}

func getCache(key string) ([]byte, bool) {
	// Read the data from the cache file
	data, err := os.ReadFile(cacheFilePath(key))
	if err != nil {
		if os.IsNotExist(err) {
			// If the file doesn't exist, return nil and false
			return nil, false
		}
		panic(err)
	}

	return data, true
}