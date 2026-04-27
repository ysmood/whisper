//go:build windows

package main

import (
	"net"
	"os/user"
	"strings"

	"github.com/Microsoft/go-winio"
)

func defaultAgentAddr() string {
	u, err := user.Current()
	if err != nil {
		exit(err)
	}
	// user.Username is typically "DOMAIN\\User" on Windows; pipe names cannot
	// contain backslashes after the leading "\\.\pipe\" prefix.
	name := u.Username
	if i := strings.LastIndex(name, `\`); i >= 0 {
		name = name[i+1:]
	}
	return `\\.\pipe\whisper-agent-` + name
}

func dialAgent(addr string) (net.Conn, error) {
	return winio.DialPipe(addr, nil)
}

func listenAgent(addr string) (net.Listener, error) {
	// SDDL: protected DACL granting GenericAll only to the pipe owner.
	// This prevents other local users (and Administrators by default would
	// still bypass via SeTakeOwnership, but cannot read in-flight data).
	cfg := &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;OW)"}
	return winio.ListenPipe(addr, cfg)
}
