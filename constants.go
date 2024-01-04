package main

import (
	"os"
	"path/filepath"
)

var SSH_DIR = func() string {
	p, err := os.UserHomeDir()
	if err != nil {
		exit(err)
	}

	return filepath.Join(p, ".ssh")
}()

var WHISPER_DEFAULT_KEY = os.Getenv("WHISPER_DEFAULT_KEY")

var WHISPER_PASSPHRASE = os.Getenv("WHISPER_PASSPHRASE")

var WHISPER_AGENT_ADDR = os.Getenv("WHISPER_AGENT_ADDR")

const WHISPER_AGENT_ADDR_DEFAULT = "127.0.0.1:57217"

var AS_AGENT_FLAG = "run-as-agent"
