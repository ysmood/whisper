package main

import (
	"os"
	"path/filepath"

	"github.com/ysmood/goe"
)

var DEFAULT_KEY_NAME = func() string {
	p, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	return filepath.Join(p, ".ssh", "id_ecdsa")
}()

var WHISPER_AGENT_ADDR = goe.Get("WHISPER_AGENT_ADDR", "127.0.0.1:57217")

var AGENT_FLAG = "run-as-agent"
