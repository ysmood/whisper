package main

import (
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"time"

	whisper "github.com/ysmood/whisper/lib"
	"github.com/ysmood/whisper/lib/secure"
)

func runAsAgent() {
	log.Println("whisper agent started, version:", whisper.APIVersion)

	whisper.NewAgentServer().Serve(WHISPER_AGENT_ADDR)
}

func startAgent() {
	running, err := whisper.IsAgentRunning(WHISPER_AGENT_ADDR, whisper.APIVersion)
	if err != nil {
		exit(err)
	}

	if running {
		return
	}

	exePath, err := os.Executable()
	if err != nil {
		exit(err)
	}

	cmd := exec.Command(exePath, "-"+AGENT_FLAG)

	err = cmd.Start()
	if err != nil {
		exit(err)
	}

	err = cmd.Process.Release()
	if err != nil {
		exit(err)
	}

	log.Println("wait for background whisper agent to start ...")

	for {
		running, err := whisper.IsAgentRunning(WHISPER_AGENT_ADDR, whisper.APIVersion)
		if err != nil {
			exit(err)
		}

		if running {
			break
		}

		time.Sleep(time.Millisecond * 100)
	}

	log.Println("background whisper agent started")
}

func agentCheckPassphrase(prv whisper.PrivateKey) bool {
	r, err := whisper.IsPassphraseRight(WHISPER_AGENT_ADDR, prv)
	if err != nil {
		exit(err)
	}
	return r
}

func agentWhisper(decrypt bool, conf whisper.Config, in io.ReadCloser, out io.WriteCloser) {
	defer func() { _ = in.Close() }()
	defer func() { _ = out.Close() }()

	req := whisper.AgentReq{Decrypt: decrypt, Config: conf}

	err := whisper.CallAgent(WHISPER_AGENT_ADDR, req, in, out)
	if err != nil {
		if conf.Sign == nil && errors.Is(err, secure.ErrSignNotMatch) {
			return
		}

		exit(err)
	}
}
