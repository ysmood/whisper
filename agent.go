package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	whisper "github.com/ysmood/whisper/lib"
	"github.com/ysmood/whisper/lib/secure"
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

func agentCheckPassphrase(prv whisper.PrivateKey) bool {
	return whisper.IsPassphraseRight(WHISPER_AGENT_ADDR, prv)
}

func agentWhisper(decrypt bool, addPubKey string, conf whisper.Config, inFile, outFile string) {
	in := getInput(inFile)
	defer func() { _ = in.Close() }()

	out := getOutput(outFile)
	defer func() { _ = out.Close() }()

	req := whisper.AgentReq{Decrypt: decrypt, Config: conf}

	if decrypt {
		pub := extractPublicKey(in)
		if len(req.Config.Public) == 0 {
			req.Config.Public = append(req.Config.Public, pub)
		}
	} else {
		req.PublicKey = prefixPublicKey(addPubKey, out)
	}

	defer func() {
		if err := recover(); err != nil {
			fmt.Fprintln(out)
			fmt.Fprintln(out, err)
		}
	}()

	whisper.CallAgent(WHISPER_AGENT_ADDR, req, in, out)
}

// If there's no public key, the output will be prefixed with "_".
// If the public key is remote, the output will be prefixed with "@", the prefix will end with space.
// If the public key is local, the output will be prefixed with ".", the prefix will end with space.
func prefixPublicKey(publicKey string, out io.Writer) secure.KeyWithFilter {
	if publicKey == "." {
		publicKey = pubKeyName(DEFAULT_KEY_NAME)
	}

	if publicKey == "" {
		_, err := out.Write([]byte("_"))
		if err != nil {
			panic(err)
		}
		return secure.KeyWithFilter{}
	}

	key := getPublicKey(publicKey)

	_, remote := extractRemotePublicKey(publicKey)

	var err error
	if remote {
		_, err = out.Write([]byte(publicKey))
	} else {
		_, err = out.Write([]byte("." + base64.StdEncoding.EncodeToString(key.Key) + ":" + key.Filter))
	}
	if err != nil {
		panic(err)
	}

	_, err = out.Write([]byte(" "))
	if err != nil {
		panic(err)
	}

	return key
}

func extractPublicKey(in io.Reader) secure.KeyWithFilter {
	buf := make([]byte, 1)
	_, err := in.Read(buf)
	if err != nil {
		panic(err)
	}

	getRawPrefix := func() string {
		raw := []byte{}
		for {
			_, err := in.Read(buf)
			if err != nil {
				panic(err)
			}

			if buf[0] == ' ' {
				break
			}

			raw = append(raw, buf[0])
		}

		return string(raw)
	}

	switch buf[0] {
	case '@':
		raw := getRawPrefix()
		return getPublicKey("@" + raw)
	case '.':
		raw := strings.Split(getRawPrefix(), ":")
		rawKey, filter := raw[0], raw[1]

		key, err := base64.StdEncoding.DecodeString(rawKey)
		if err != nil {
			panic(err)
		}

		return secure.KeyWithFilter{
			Key:    key,
			Filter: filter,
		}
	default:
		return secure.KeyWithFilter{
			Key: getKey(pubKeyName(DEFAULT_KEY_NAME)),
		}
	}
}
