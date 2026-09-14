---
name: whisper-cli
description: Encrypt, decrypt, sign, and verify files and secrets with the `whisper` CLI (github.com/ysmood/whisper), using existing SSH keys or GitHub users' public keys, including batch-encrypting a secrets folder with whisper.json. Use when a task mentions whisper encryption, `.wsp` files, `whisper.json`, or sharing secrets encrypted to SSH or GitHub keys. Not for OpenAI Whisper speech-to-text.
---

# whisper CLI

`whisper` encrypts data with public-key cryptography, using keys people already have: local SSH keys or the keys GitHub publishes at `https://github.com/<id>.keys`. It supports Ed25519, ECDSA, and RSA. Encrypted files use the `.wsp` extension.

Check that it is installed:

```bash
whisper -v    # prints the version, e.g. v0.10.0
```

If it is missing, run `go install github.com/ysmood/whisper@latest`, or download a binary from https://github.com/ysmood/whisper/releases. The sender and the recipients should use the same release. Files from a different wire-format version are rejected.

## How a command is interpreted

- **One or more `-e` flags means encrypt. No `-e` means decrypt.** There is no separate decrypt flag.
- **Put every flag before the input file.** Flags after the first positional argument are silently ignored. `whisper secret.wsp -o out.txt` prints the plaintext to stdout, creates no file, and exits 0.
- **Input** is the positional file argument, `-i <file or https URL>`, or stdin.
- **Output** is stdout by default. `-o <file>` writes to a file instead, creating parent directories; the file gets `0600` permissions. Encrypted output is binary, so always redirect it or use `-o`.
- **Errors** go to stderr as `Error: ...` with exit code 1. Always check the exit code. In some failure cases whisper has already written output before it reports the error (see [Signing](#signing-and-verifying)).

## Key formats for `-e` and `-s`

| Value                   | Meaning                                                                          |
| ----------------------- | -------------------------------------------------------------------------------- |
| `path/to/key.pub`       | A local public key or `authorized_keys` file. Only its first key is used.        |
| `@jack`                 | GitHub user `jack`. Only the **first** key GitHub lists for them is used.         |
| `@jack:ed25519`         | Jack's first GitHub key whose line contains the substring `ed25519`.             |
| `@https://host/x.keys`  | Any HTTPS URL serving `authorized_keys`-style lines.                             |

Gotchas:

- **Don't quote `~`.** `-e='~/.ssh/id_ed25519.pub'` fails because whisper does not expand `~`. Write `-e ~/.ssh/id_ed25519.pub` or `-e "$HOME/.ssh/id_ed25519.pub"`.
- **A recipient with several GitHub keys can only decrypt with the one you selected.** If they will decrypt on a machine holding a different key, add a selector. Any unique substring of that key's line works, such as a fragment of its base64.
- **Selectors don't work with `@https://` URLs.** The `:selector` suffix is misparsed there. Download the key file, keep the one line you need, and pass it as a local path.
- **Remote keys are cached indefinitely** in the user cache directory (`~/Library/Caches/whisper` on macOS, `~/.cache/whisper` on Linux). That includes a failed lookup such as a mistyped GitHub ID. After a recipient rotates their keys, or after fixing a typo, run `whisper -clear-cache`.

## Common tasks

```bash
# Encrypt for yourself, then decrypt
whisper -e ~/.ssh/id_ed25519.pub secret.txt > secret.txt.wsp
whisper secret.txt.wsp                         # plaintext to stdout
whisper -o secret.txt secret.txt.wsp           # plaintext to a file

# Encrypt for several people; any one of them can decrypt
whisper -e @jack -e @tim -e ~/.ssh/id_ed25519.pub -o secret.txt.wsp secret.txt

# Pipes work too
cat secret.txt | whisper -e @jack > secret.txt.wsp

# Compress before encrypting (zstd level; decryption detects it)
whisper -c 3 -e @jack -o big.log.wsp big.log

# Base64 text output, e.g. for pasting into chat, YAML, or env vars
whisper -b -e @jack secret.txt > secret.b64
whisper -b secret.b64                          # -b is needed to decrypt it too

# Inspect a .wsp file without decrypting it
whisper -m secret.txt.wsp
```

`-m` prints the wire format, whether the file is signed, the claimed signer, the recipients, and whether it is compressed. Recipients and signers show a readable name only when they were given as `@...`. Local keys appear as a short hex hash, and the signer then shows as `""`.

### Which private key decrypts

If `-p` is not given, whisper tries these in order:

1. `WHISPER_KEY_PATH`. This is the default value of `-p`, and it disables the steps below.
2. `WHISPER_DTM_KEY`, the passphrase of a deterministic key (see [Generating keys](#generating-keys)).
3. `WHISPER_KEY`, the private key contents, with `WHISPER_PASSPHRASE` if it is encrypted.
4. Any `~/.ssh/*.pub` that is one of the file's recipients. The private key must sit next to it without the `.pub` extension.
5. `~/.ssh/id_ed25519`.

When you already know which key to use, pass `-p ~/.ssh/<key>` explicitly.

## Signing and verifying

Signing proves who sent a file. `-m` only shows who *claims* to have sent it.

```bash
# Sender: sign with your own key and encrypt for jack. Name your key either
# by GitHub ID, so recipients see it in -m ...
whisper -s @your-github-id -e @jack -o secret.txt.wsp secret.txt
# ... or by local path, with -p pointing at the matching private key.
whisper -s ~/.ssh/id_ed25519.pub -p ~/.ssh/id_ed25519 -e @jack -o secret.txt.wsp secret.txt

# Recipient: decrypt and verify the expected sender
whisper -s @sender-github-id -o secret.txt secret.txt.wsp
```

- **Match the `-s` key to the signing private key.** When encrypting, the signing key is `-p`, `WHISPER_DTM_KEY`, `WHISPER_KEY`, or else `~/.ssh/id_ed25519`, with no search of `~/.ssh`. If the `-s` public key doesn't match it, whisper fails with `public and private key not match`.
- **Always pass `-s` when decrypting a signed file.** Without it, whisper may exit 1 with `sign mismatch` even though decryption worked. It does so when no agent is running and exits 0 when one is.
- **On `sign mismatch`, don't trust or keep the output.** Plaintext is streamed, so it has already been written to stdout or the `-o` file. If you passed the right `-s`, the file was tampered with or came from someone else. Delete the output and tell the user.

## Non-interactive use (agents, scripts, CI)

Passphrase prompts need a terminal. If stdin is a pipe or there is no TTY, whisper fails with `stdin is used for piping, can't read passphrase from it`. Choose one of these approaches:

- **Use the agent cache.** This is best when a person is available. Ask the user to run `whisper -add ~/.ssh/<key>` in their own terminal. It starts the background agent and caches the unlocked key in memory. Later whisper commands that use that key need no passphrase, until the agent restarts or someone runs `whisper -clear-cache`.
- **Use `WHISPER_PASSPHRASE`.** It must already be set in the environment, e.g. a CI secret.
- **Use `WHISPER_KEY`.** Store the private key contents in a CI secret, typically a dedicated key with no passphrase.

Never ask the user to paste a passphrase or private key into the conversation, and never put one directly on a command line, where it would land in shell history and process listings. Don't echo decrypted secrets back to the user unless they asked to see them. Prefer `-o` to a file.

## Agent server

```bash
whisper -agent                 # start the background agent if it isn't running
whisper -add ~/.ssh/id_ed25519 # start it and cache this key (prompts for the passphrase)
whisper -clear-cache           # forget cached keys and cached remote public keys
```

The agent listens on a per-user Unix socket in the cache directory, or on a named pipe on Windows. `WHISPER_AGENT_ADDR` overrides that address. **Keep a custom socket path short**, under about 100 bytes. A longer path fails to bind, and `whisper -agent` then hangs forever at `wait for background whisper agent to start ...`.

## Batch encryption (`whisper.json`)

To manage a whole folder of secrets for a team, with groups, admins, and change detection:

```bash
whisper -be whisper.json    # encrypt into outDir
whisper -bd whisper.json    # decrypt back to the original paths (overwrites them)
```

Before writing or editing a batch config, or when batch decryption misbehaves, read [references/batch.md](references/batch.md). It covers the config format, path rules, and two `-bd` pitfalls:
- `-bd` silently stops at the first file you're not a recipient of.
- `-bd` panics when `outDir` is missing.

## Generating keys

`whisper -gen-key <path>` writes `<path>` and `<path>.pub`. It refuses to overwrite an existing key and is **interactive only**: it asks for a passphrase, a comment, and whether to make the key deterministic.

A deterministic key is derived entirely from its passphrase, so the same passphrase regenerates it on any machine. That makes it only as strong as the passphrase. Without a TTY, use `ssh-keygen -t ed25519 -f <path>` instead, or ask the user to run the command.

## Troubleshooting

| Error message contains | Cause and fix |
| --- | --- |
| `not a recipient, the data is not encrypted for your public key` | None of your keys can decrypt it. Compare `whisper -m` with your keys. If the sender used `@you` and you have several GitHub keys, ask them to re-encrypt with `@you:<selector>`, or pass `-p` for the matching key. |
| `open ~/...: no such file or directory` | A quoted `~` was not expanded. Use `$HOME`. |
| `the input is base64 encoded, you might want to add -b flag` | Add `-b`. |
| `whisper file format version mismatch` | Created by a different whisper release, or not a whisper file. Align the versions. |
| `stdin is used for piping, can't read passphrase from it` | See [Non-interactive use](#non-interactive-use-agents-scripts-ci). |
| `sign mismatch` | Wrong `-s`, a missing `-s` on a signed file, or tampering. See [Signing](#signing-and-verifying). |
| `public and private key not match` | The `-s` key isn't the public half of the signing private key. Pass the matching `-p`. |
| `failed to parse public key ... ssh: no key found` with an `@id` | The GitHub user doesn't exist or has no SSH keys, and that result is now cached. Fix the ID, then run `whisper -clear-cache`. |
| `whisper -agent` hangs | `WHISPER_AGENT_ADDR` is too long, or its directory isn't writable. Stop the command and shorten the path. |
| `panic: ... nil pointer dereference` from `-bd` | The config's `outDir` doesn't exist. |
| No error, but the `-o` file wasn't created and the output went to stdout | A flag came after the input file and was ignored. Move all flags before the file. |
