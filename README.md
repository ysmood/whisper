# Overview

A simple lib to encrypt, decrypt data with [Public-key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography).
Now [ED25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519), [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm),
and [RSA](<https://en.wikipedia.org/wiki/RSA_(cryptosystem)>) are supported.

Features:

- Use the existing ssh key pairs and github public key url, no need to generate new key pair.
- Auto find the right key to decrypt.
- Encrypt data for multiple recipients.
- [ssh-agent](https://en.wikipedia.org/wiki/Ssh-agent) like server to cache the private key passphrase.
- Optional signing for integrity check.
- Lower overhead and small wire format.
- Streamlined design for large file encryption.

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
ssh-keygen -t ed25519 -N "" -f id_ed25519

echo 'hello world!' > hello.txt

# Encrypt file hello.txt to a whisper file hello.wsp .
# It will auto start a agent server to cache the passphrase so you don't have to retype it.
whisper -e='id_ed25519.pub' hello.txt > hello.wsp

# Decrypt file encrypted to stdout
whisper -p='id_ed25519' hello.wsp
# hello world!

# You can also use it as a pipe
cat hello.txt | whisper -e='id_ed25519.pub' > hello.wsp
cat hello.wsp | whisper -p='id_ed25519'
```

You can also use a url for a remote public key file.
Here we use my public key on github to encrypt the data.
Github generally exposes your public key file at `@https://github.com/{YOUR_ID}.keys`.

```bash
# For github you can use the user id directly.
whisper -e='@ysmood' hello.txt > hello.wsp

# For other sites you can use the full url.
whisper -e='@https://github.com/ysmood.keys' hello.txt > hello.wsp

# A authorized_keys file may contain several keys, you can add a suffix to select a specific key to encrypt.
# 'ed25519' is the substring of the key we want to use.
whisper -e='@ysmood:ed25519' hello.txt > hello.wsp

# Encrypt content for multiple recipients, such as Jack and Tim.
whisper -e='@jack' -e='@tim' hello.txt > hello.wsp

# Decrypt on Jack's machine, the machine has Jack's private key.
whisper hello.wsp

# To sign and encrypt the data, you can use the `-s` flag.
whisper -s='@ysmood' -e='@jack' hello.txt > hello.wsp

# To verify the signature and decrypt the data. If -s flag is not provided, it will only decrypt the data.
whisper -s='@ysmood' hello.wsp
```
