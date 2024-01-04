package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"

	whisper "github.com/ysmood/whisper/lib"
	"github.com/ysmood/whisper/lib/secure"
)

func runAsAgent() {
	fmt.Fprintf(os.Stderr, "whisper agent started on %s, version: %s\n", WHISPER_AGENT_ADDR, whisper.APIVersion)

	whisper.NewAgentServer().Serve(WHISPER_AGENT_ADDR)
}

func ensureAgent(background bool) bool {
	running, err := whisper.IsAgentRunning(WHISPER_AGENT_ADDR, whisper.APIVersion)
	if err != nil {
		exit(err)
	}

	if running {
		return false
	}

	if background {
		launchBackgroundAgent()
		return true
	}

	s := whisper.NewAgentServer()

	l, err := net.Listen("tcp4", ":0")
	if err != nil {
		exit(err)
	}

	go s.Listen(l)

	WHISPER_AGENT_ADDR = l.Addr().String()

	return false
}

func launchBackgroundAgent() {
	exePath, err := os.Executable()
	if err != nil {
		exit(err)
	}

	cmd := exec.Command(exePath, "-"+AS_AGENT_FLAG)

	err = cmd.Start()
	if err != nil {
		exit(err)
	}

	err = cmd.Process.Release()
	if err != nil {
		exit(err)
	}

	fmt.Fprintln(os.Stderr, "wait for background whisper agent to start ...")

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

	fmt.Fprintln(os.Stderr, "background whisper agent started")
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
