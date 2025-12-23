package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	whisper "github.com/ysmood/whisper/lib"
	"github.com/ysmood/whisper/lib/secure"
)

func agent() whisper.AgentClient {
	return whisper.NewAgentClient(WHISPER_AGENT_ADDR)
}

func runAsAgentServer() {
	fmt.Fprintf(os.Stderr, "whisper agent started on %s, version: %s\n", WHISPER_AGENT_ADDR, whisper.APIVersion)

	whisper.NewAgentServer().Serve(WHISPER_AGENT_ADDR)
}

func isAgentServerRunning() bool {
	running, err := agent().IsServerRunning(whisper.APIVersion)
	if err != nil {
		exit(err)
	}

	return running
}

func launchAgentServer() {
	if isAgentServerRunning() {
		return
	}

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

	for !isAgentServerRunning() {

		time.Sleep(time.Millisecond * 100)
	}

	fmt.Fprintln(os.Stderr, "background whisper agent started")
}

func agentCheckPassphrase(prv whisper.PrivateKey) bool {
	r, err := agent().IsPassphraseRight(prv)
	if err != nil {
		exit(err)
	}
	return r
}

func agentWhisper(conf whisper.Config, in io.ReadCloser, out io.WriteCloser) error {
	defer func() { _ = in.Close() }()
	defer func() { _ = out.Close() }()

	err := agent().Whisper(conf, in, out)
	if conf.Sign == nil && errors.Is(err, secure.ErrSignMismatch) {
		return nil
	}
	return err
}

var ErrWrongPassphrase = errors.New("wrong passphrase")

func agentAddPassphrase(path string) {
	launchAgentServer()

	prv, err := whisper.ReadKey(path)
	if err != nil {
		exit(fmt.Errorf("failed to read private key: %w", err))
	}

	if !agentCheckPassphrase(whisper.PrivateKey{
		Data:       prv,
		Passphrase: getPassphrase(path),
	}) {
		exit(ErrWrongPassphrase)
	}
}
