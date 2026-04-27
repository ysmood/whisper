//go:build !windows

package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
)

func defaultAgentAddr() string {
	base, err := os.UserCacheDir()
	if err != nil {
		exit(err)
	}
	return filepath.Join(base, "whisper", "agent.sock")
}

func dialAgent(addr string) (net.Conn, error) {
	return net.Dial("unix", addr)
}

func listenAgent(addr string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(addr), 0o700); err != nil {
		return nil, err
	}
	if err := os.Remove(addr); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", addr)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(addr, 0o600); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}
