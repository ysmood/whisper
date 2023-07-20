<!-- markdownlint-disable MD010 -->

# Overview

A simple lib to encrypt, decrypt data with [ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography).

## Installation

Use it as [lib](https://pkg.go.dev/github.com/ysmood/whisper/lib) or CLI tool.

Go to the [release page](https://github.com/ysmood/whisper/releases) to download the CLI binary.

If you have golang installed:

```bash
go install github.com/ysmood/whisper@latest
```

## CLI Usage

```bash
whisper -g
# Keys generated successfully: ecc_key

echo 'hello world!' | whisper
# FVPmYc4x1JilPtF8rMs0n2OlX2

echo 'FVPmYc4x1JilPtF8rMs0n2OlX2' | whisper -d
# hello world!
```
