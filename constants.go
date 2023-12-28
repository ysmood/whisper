package main

import (
	"os"
	"path/filepath"

	"github.com/ysmood/goe"
)

var SSH_DIR = func() string {
	p, err := os.UserHomeDir()
	if err != nil {
		exit(err)
	}

	return filepath.Join(p, ".ssh")
}()

var WHISPER_DEFAULT_KEY = func() string {
	key := os.Getenv("WHISPER_DEFAULT_KEY")

	if key == "" {
		key = filepath.Join(SSH_DIR, "id_ed25519")
	}

	return key
}()

var WHISPER_PASSPHRASE = os.Getenv("WHISPER_PASSPHRASE")

var WHISPER_AGENT_ADDR = goe.Get("WHISPER_AGENT_ADDR", "127.0.0.1:57217")

var AGENT_FLAG = "run-as-agent"
