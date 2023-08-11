package main

import (
	"log"
	"os"
	"os/exec"
	"time"

	whisper "github.com/ysmood/whisper/lib"
)

func runAsAgent() {
	log.Println("whisper agent started, version:", whisper.Version())

	whisper.NewAgentServer().Serve(WHISPER_AGENT_ADDR)
}

func startAgent() {
	if whisper.IsAgentRunning(WHISPER_AGENT_ADDR, whisper.Version()) {
		return
	}

	exePath, err := os.Executable()
	if err != nil {
		panic(err)
	}

	cmd := exec.Command(exePath, "-"+AGENT_FLAG)

	err = cmd.Start()
	if err != nil {
		panic(err)
	}

	err = cmd.Process.Release()
	if err != nil {
		panic(err)
	}

	log.Println("wait for background whisper agent to start ...")

	for !whisper.IsAgentRunning(WHISPER_AGENT_ADDR, whisper.Version()) {
		time.Sleep(time.Millisecond * 100)
	}

	log.Println("background whisper agent started")
}

func callAgent(decrypt bool, conf whisper.Config, inFile, outFile string) bool {
	in := getInput(inFile)
	defer func() { _ = in.Close() }()

	out := getOutput(outFile)
	defer func() { _ = out.Close() }()

	req := whisper.AgentReq{Decrypt: decrypt, Config: conf}

	return whisper.CallAgent(WHISPER_AGENT_ADDR, req, in, out)
}
