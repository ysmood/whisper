<!-- markdownlint-disable MD010 -->

# Overview

A simple lib to encrypt, decrypt data with [Public-key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography).
Now only [RSA](<https://en.wikipedia.org/wiki/RSA_(cryptosystem)>) and [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) are supported.

## CLI tool

### Installation

Use it as [lib](https://pkg.go.dev/github.com/ysmood/whisper/lib) or CLI tool.

Go to the [release page](https://github.com/ysmood/whisper/releases) to download the CLI binary.

If you have golang installed:

```bash
go install github.com/ysmood/whisper@latest
```

### Usage

Here is a simple example to encrypt and decrypt for yourself, the encrypted data can only be decrypted by your private key.

```bash
# generate a key pair
ssh-keygen -t ecdsa

echo 'hello world!' > plain

# Encrypt file plain to file encrypted
# It will auto start a agent server to cache the passphrase so you don't have to retype it.
whisper plain > encrypted

# Decrypt file encrypted to stdout
whisper -d encrypted
# hello world!

# You can also use it as a pipe
cat plain | whisper > encrypted
cat encrypted | whisper -d
```

Here is an example to encrypt and decrypt for others, the encrypted data can only be decrypted by their public key.
Suppose we have key pair for Jack `jack.pub` and `jack`, and key pair for Tim `tim.pub` and `tim`.

```bash
# Encrypt file that can only be decrypted by Tim
whisper -k 'jack' -p='tim.pub' plain > encrypted

# Decrypt file encrypted to stdout
whisper -d -k='tim' -p 'jack' encrypted
```

You can also use a url for a remote public key file.
Here we use my public key on github to encrypt the data.
Github generally exposes your public key file at `@https://github.com/{YOUR_ID}.keys`.

```bash
whisper -p='@https://github.com/ysmood.keys' plain > encrypted

# A shortcut the same as above
whisper -p='@ysmood' plain > encrypted

# A authorized_keys file may contain several keys, you can add a suffix to select a specific key.
# 'tbml' is the substring of the key content we want to use.
whisper -p='@ysmood:ecdsa' plain > encrypted

# Encrypt content for multiple recipients, such as Jack and Tim.
whisper -a='@ysmood' -p='@jack' -p='@tim' plain > encrypted

# Or embed the default public key file to the output.
whisper -a=. -p='@jack' -p='@tim' plain > encrypted

# Decrypt on Jack's machine, the machine has Jack's private key.
whisper -d encrypted
```
