<!-- markdownlint-disable MD010 -->

# Overview

A simple tool to encrypt, decrypt, sign, and verify data with [ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography).

## Installation

Go to the [release page](https://github.com/ysmood/whisper/releases).

If you have golang installed:

```bash
go install github.com/ysmood/whisper@latest
```

## Usage

```bash
whisper -g
# Keys generated successfully: ecc_key

echo 'hello world!' | whisper
# FVPmYc4x1JilPtF8rMs0n2OlX2

echo 'FVPmYc4x1JilPtF8rMs0n2OlX2' | whisper -d
# hello world!
```

Use it as lib: [link](https://pkg.go.dev/github.com/ysmood/whisper)
