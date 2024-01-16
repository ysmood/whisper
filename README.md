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

### Encrypt and decrypt with local keys

Here is a simple example to encrypt and decrypt for yourself. The encrypted data can only be decrypted by your private key.

```bash
# Skip this if already have a key pair.
whisper -gen-key ~/.ssh/id_ed25519

echo 'hello world!' > hello.txt

# Encrypt file hello.txt to a whisper file hello.wsp .
# It will auto start a agent server to cache the passphrase so you don't have to retype it.
whisper -e='~/.ssh/id_ed25519.pub' hello.txt > hello.wsp

# Decrypt file encrypted to stdout.
whisper hello.wsp
# hello world!

# Piping is also supported.
cat hello.txt | whisper -e='~/.ssh/id_ed25519.pub' > hello.wsp
cat hello.wsp | whisper
```

### Encrypt and decrypt with remote keys

You can also use a url for a remote public key file.
Here we use my public key on github to encrypt the data.
Github generally exposes your public key file at `@https://github.com/{YOUR_ID}.keys`.

```bash
# For github, you can use the user id directly.
# Here the user id is 'ysmood'.
whisper -e='@ysmood' hello.txt > hello.wsp

# For other sites you can use the full url.
whisper -e='@https://gitlab.com/jack.keys' hello.txt > hello.wsp

# A authorized_keys file may contain several keys,
# you can add a suffix to select a specific key to encrypt.
# 'ed25519' is the substring of the key we want to use.
whisper -e='@ysmood:ed25519' hello.txt > hello.wsp

# Encrypt content for multiple recipients, such as Jack and Tim.
whisper -e='@jack' -e='@tim' hello.txt > hello.wsp

# Decrypt on Jack's machine, the machine has Jack's private key.
whisper hello.wsp

# To sign and encrypt the data, you can use the `-s` flag.
whisper -s='@ysmood' -e='@jack' hello.txt > hello.wsp

# Print the meta data of the whisper file to see who is the sender.
whisper -m hello.wsp

# To verify the signature and decrypt the data.
# If -s flag is not provided, it will only decrypt the data.
whisper -s='@ysmood' hello.wsp
```

The input can also be file url.

### Batch encrypt and decrypt

Create a json file `whisper.json` with the content:

```json
{
  "$schema": "https://raw.githubusercontent.com/ysmood/whisper/main/batch_schema.json",
  "files": {
    "secrets/backend": ["@jack"],
    "secrets/db.txt": ["@tom"]
  },
  "outDir": "vault"
}
```

Then run:

```bash
whisper -be whisper.json
```

It will encrypt the files in folder `secrets/backend` for Jack and encrypt file `secrets/db.txt` for Tom,
they will be saved to folder `vault`.

To decrypt in batch, run:

```bash
whisper -bd whisper.json
```

Or you can decrypt a single file directly:

```bash
whisper vault/secrets/db.txt.wsp
```

If you have a lot of members to manage, the batch config file supports grouping,
the `$` prefix means a group name:

```jsonc
{
  "$schema": "https://raw.githubusercontent.com/ysmood/whisper/main/batch_schema.json",
  "groups": {
    "$frontend": ["@mike", "@tim"],
    "$backend": ["$frontend", "@jack"] // group reference can be recursive
  },
  "admins": ["@ci-robot"], // the users who can decrypt all the files
  "files": {
    "secrets/backend": ["$backend"],
    "secrets/frontend": ["$frontend", "@tom"],
    "secrets/frontend/mongo": ["@joy"] // add the user to the file that is already set by previous line
  },
  "outDir": "vault"
}
```

### Agent and cache

The agent server is for caching the private key passphrase, so you don't have to retype it every time.
To start the agent server, run:

```bash
# Add the key to the agent.
whisper -add ~/.ssh/id_ed25519
```

To remove the key from the agent, run:

```bash
whisper -clear-cache
```

### Deterministic private key generation

When using the `-gen-key` flag, it will ask you whether to generate a deterministic key or not,
if you enter `yes`, the key will be generated based on the passphrase itself,
so that you can regenerate the same private key on any device as long as you remember the passphrase.
This is useful if you don't want to backup the key, but it's less secure than random key, you must use a strong passphrase.
