# Batch encryption with `whisper.json`

Batch mode encrypts a set of files or folders, each for its own list of recipients, into an output folder that is safe to commit. Team members decrypt it back in place.

```bash
whisper -be whisper.json               # encrypt everything the config lists
whisper -p <key> -bd whisper.json      # decrypt the files you are a recipient of
```

Run both commands from the directory that contains `whisper.json` (see "Paths" below).

## Config format

```jsonc
{
  "$schema": "https://raw.githubusercontent.com/ysmood/whisper/main/batch_schema.json",
  "groups": {
    "$frontend": ["@mike", "@tim"],
    "$backend": ["$frontend", "@jack"]      // groups can include other groups
  },
  "admins": ["@ci-robot"],                   // added as a recipient of every file
  "files": {
    "secrets/backend": ["$backend"],         // a directory: every file under it, recursively
    "secrets/frontend": ["$frontend", "@tom"],
    "secrets/frontend/mongo": ["@joy"]       // overlapping entries merge their recipients
  },
  "excludeFiles": ["secrets/backend/tmp"],
  "outDir": "vault"
}
```

The file is plain JSON. The comments above are for illustration only.

| Field          | Meaning                                                                                            |
| -------------- | -------------------------------------------------------------------------------------------------- |
| `groups`       | Named recipient lists. Names must start with `$`. Nesting is allowed; circular references error out. |
| `admins`       | Recipients added to every file.                                                                    |
| `files`        | Path (file or directory) → recipients. Use `/` as the separator on every OS.                       |
| `excludeFiles` | Paths to skip. This is a plain string-prefix match, so `secrets/tmp` also excludes `secrets/tmp2`. |
| `outDir`       | Where the `.wsp` files are written.                                                                |

A recipient can be any of the following:

- `@github-id`, or `@github-id:selector` to pick one key.
- `@https://host/path.keys`.
- `$group`.
- A local public-key file path.

## Paths

- `files`, `excludeFiles`, `outDir`, and local key paths listed directly in `files` or `admins` are resolved relative to the config file's directory.
- Local key paths listed inside `groups` are resolved relative to the current working directory. Running from the config directory makes both rules agree.
- A `files` entry that does not exist prints `[skip] not exists: <path>` and is ignored.

## What `-be` produces

For each input file `<path>`:

- `<outDir>/<path>.wsp` is the encrypted file. It is always zstd-compressed at the highest level.
- `<outDir>/<path>.wsp.digest` is a SHA-256 over the wire-format version, the recipients' public keys, and the plaintext. On the next run, a file whose digest matches prints `[skip] not changed` and is not re-encrypted. Adding or removing a recipient changes the digest, so the affected files are re-encrypted.

Delete a `.digest` file to force re-encryption. The digest is unsalted. If a secret is short and guessable, such as a 4-digit PIN, its digest can be brute-forced. Keep such values out of batch mode or don't commit the digests.

`-be` needs no private key.

## What `-bd` does

- It walks `outDir` for `*.wsp` files and writes each plaintext back to its original path next to the config. **Existing files at those paths are overwritten.**
- The private key comes from `-p`, or from the usual auto-detection (see SKILL.md). It is resolved once and reused for every file, so pass `-p` explicitly when you have more than one key.

### `-bd` gotchas

- **It stops at the first file you can't read.** When it hits a file you are not a recipient of, it prints `[skip] not a recipient: <file>`, stops processing the remaining files, and still exits 0. Files are visited in lexical path order. If that message appears, don't assume everything else was decrypted. Use the per-file loop below.
- **It panics if `outDir` doesn't exist**, e.g. nothing has been encrypted yet or the config path is wrong. The panic is `nil pointer dereference`. Check that the folder exists first.

### Per-file decryption

This loop decrypts every file you are a recipient of, keeps going past the others, and reports failures. Run it from the config directory and set `OUT` to the config's `outDir`.

```bash
OUT=vault
while IFS= read -r f <&3; do
  dest="${f#"$OUT"/}"; dest="${dest%.wsp}"
  whisper -i "$f" -o "$dest" 2>/dev/null || echo "not decrypted: $f" >&2
done 3< <(find "$OUT" -name '*.wsp')
```

The file list is read from file descriptor 3 so that stdin stays free. If the key has a passphrase and the agent doesn't have it cached, whisper needs stdin to prompt for it, or `WHISPER_PASSPHRASE` must be set.
