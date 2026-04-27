package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

func cacheClear() {
	// Remove the cache directory
	err := os.RemoveAll(cacheDir())
	if err != nil {
		exit(err)
	}

	if isAgentServerRunning() {
		err = agent().ClearCache()
		if err != nil {
			exit(err)
		}
	}
}

func cacheDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		exit(err)
	}
	return filepath.Join(base, "whisper")
}

func cacheFilePath(key string) string {
	return filepath.Join(cacheDir(), hex.EncodeToString([]byte(key)))
}

func cache(key string, data any) {
	b, err := json.Marshal(data)
	if err != nil {
		exit(err)
	}

	err = os.MkdirAll(cacheDir(), 0o700)
	if err != nil {
		exit(err)
	}

	err = os.WriteFile(cacheFilePath(key), b, 0o600)
	if err != nil {
		exit(err)
	}
}

func getCache(key string, data any) bool {
	p := cacheFilePath(key)
	if _, err := os.Stat(p); err != nil {
		return false
	}

	b, err := os.ReadFile(p)
	if err != nil {
		exit(err)
	}

	err = json.Unmarshal(b, data)
	if err != nil {
		exit(err)
	}

	return true
}
