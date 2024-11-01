package main

import (
	"os"
)

var WHISPER_KEY_PATH = os.Getenv("WHISPER_KEY_PATH")

var WHISPER_KEY = os.Getenv("WHISPER_KEY")

var WHISPER_DTM_KEY = os.Getenv("WHISPER_DTM_KEY")

var WHISPER_PASSPHRASE = os.Getenv("WHISPER_PASSPHRASE")

var WHISPER_AGENT_ADDR = os.Getenv("WHISPER_AGENT_ADDR")

const WHISPER_AGENT_ADDR_DEFAULT = "127.0.0.1:57217"

const AS_AGENT_FLAG = "run-as-agent"

const WHISPER_FILE_EXT = ".wsp"

const WHISPER_DIGEST_EXT = ".digest"
