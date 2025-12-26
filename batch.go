package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	whisper "github.com/ysmood/whisper/lib"
	"github.com/ysmood/whisper/lib/secure"
	"golang.org/x/sync/errgroup"
)

type Group []string

type Batch struct {
	Groups       map[string]Group `json:"groups"`
	Admins       Group            `json:"admins"`
	Files        map[string]Group `json:"files"`
	ExcludeFiles []string         `json:"excludeFiles"`
	OutDir       string           `json:"outDir"`

	root string
}

func NewBatch(configPath string) (*Batch, error) {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read batch config file %s: %w", configPath, err)
	}

	conf := Batch{}
	err = json.Unmarshal(b, &conf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse batch config JSON: %w", err)
	}

	conf.root = filepath.Dir(configPath)

	conf.OutDir = filepath.Join(conf.root, filepath.FromSlash(conf.OutDir))

	return &conf, nil
}

func (b *Batch) GetMembers(group string) ([]string, error) {
	return b.getMembers(group, []string{})
}

var ErrCircularGroupReference = errors.New("circular group reference detected")

var ErrGroupNotDefined = errors.New("group not defined")

func (b *Batch) getMembers(group string, visited []string) ([]string, error) {
	if slices.Contains(visited, group) {
		return nil, fmt.Errorf("%w: %v", ErrCircularGroupReference, visited)
	}

	visited = append(visited, group)

	members := []string{}

	if _, ok := b.Groups[group]; !ok {
		return nil, fmt.Errorf("%w: %s", ErrGroupNotDefined, group)
	}

	// expand members if it contains other groups
	for _, member := range b.Groups[group] {
		if strings.HasPrefix(member, "$") {
			ms, err := b.getMembers(member, visited)
			if err != nil {
				return nil, fmt.Errorf("failed to expand group member %s: %w", member, err)
			}
			members = append(members, ms...)
		} else {
			members = append(members, member)
		}
	}

	return members, nil
}

func (b *Batch) ExpandGroups() (map[string][]string, error) {
	expanded := map[string][]string{}

	for k := range b.Groups {
		ms, err := b.GetMembers(k)
		if err != nil {
			return nil, fmt.Errorf("failed to expand group %s: %w", k, err)
		}
		expanded[k] = ms
	}

	return expanded, nil
}

func (b *Batch) ExpandFiles() (map[string][]string, error) {
	files := map[string]map[string]struct{}{}
	groups, err := b.ExpandGroups()
	if err != nil {
		return nil, fmt.Errorf("failed to expand groups for files: %w", err)
	}

	for p, members := range b.Files {
		expanded := map[string]struct{}{}
		members = append(members, b.Admins...)
		for _, member := range members {
			switch {
			case strings.HasPrefix(member, "$"):
				if _, ok := groups[member]; !ok {
					return nil, fmt.Errorf("%w: %s", ErrGroupNotDefined, member)
				}
				for _, m := range groups[member] {
					expanded[m] = struct{}{}
				}
			case strings.HasPrefix(member, "@"):
				expanded[member] = struct{}{}
			default:
				expanded[filepath.Join(b.root, member)] = struct{}{}
			}
		}

		files[p] = expanded
	}

	expanded := map[string]map[string]struct{}{}
	for p, members := range files {
		p := filepath.FromSlash(p)
		rp := filepath.Join(b.root, p)

		stat, err := os.Stat(rp)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "[skip] not exists: %s\n", rp)
				continue
			}
			return nil, fmt.Errorf("failed to stat file/dir %s: %w", rp, err)
		}

		if stat.IsDir() {
			err := filepath.WalkDir(rp, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return fmt.Errorf("walk error at %s: %w", path, err)
				}

				if d.IsDir() {
					return nil
				}

				path, err = filepath.Rel(b.root, path)
				if err != nil {
					return fmt.Errorf("failed to get relative path for %s: %w", path, err)
				}

				if b.isExcluded(path) {
					return nil
				}

				for m := range members {
					if expanded[path] == nil {
						expanded[path] = map[string]struct{}{}
					}
					expanded[path][m] = struct{}{}
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("failed to walk directory %s: %w", rp, err)
			}
		} else {
			for m := range members {
				if expanded[p] == nil {
					expanded[p] = map[string]struct{}{}
				}
				expanded[p][m] = struct{}{}
			}
		}
	}

	res := map[string][]string{}

	for p, members := range expanded {
		for m := range members {
			res[p] = append(res[p], m)
		}
		sort.Strings(res[p])
	}

	return res, nil
}

func (b *Batch) isExcluded(path string) bool {
	for _, p := range b.ExcludeFiles {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func (b *Batch) Encrypt() error {
	files, err := b.ExpandFiles()
	if err != nil {
		return fmt.Errorf("failed to expand files for encryption: %w", err)
	}

	eg := errgroup.Group{}

	for p, members := range files {
		eg.Go(func() error {
			err = os.MkdirAll(filepath.Join(b.OutDir, filepath.Dir(p)), 0o755)
			if err != nil {
				return fmt.Errorf("failed to create output directory for %s: %w", p, err)
			}

			outPath := filepath.Join(b.OutDir, p+WHISPER_FILE_EXT)
			inPath := filepath.Join(b.root, p)
			input := getInput(inPath, "")
			output := getOutput(outPath)

			conf := whisper.Config{
				GzipLevel: 9,
				Public:    getPublicKeys(members),
			}

			same, err := b.same(conf, inPath, outPath)
			if err != nil {
				return fmt.Errorf("failed to check if file %s changed: %w", inPath, err)
			}
			if same {
				_, _ = fmt.Fprintf(os.Stderr, "[skip] not changed: %s\n", inPath)
				return nil
			}

			err = run(conf, input, output)
			if err != nil {
				return fmt.Errorf("failed to encrypt file %s: %w", inPath, err)
			}

			_, _ = fmt.Fprintf(os.Stdout, "[encrypted] %s -> %s\n", inPath, outPath)

			return nil
		})
	}

	return eg.Wait()
}

func (b *Batch) Decrypt(privateKeyPath string) error {
	files := []string{}
	err := filepath.WalkDir(b.OutDir, func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() && filepath.Ext(path) == WHISPER_FILE_EXT {
			path, err := filepath.Rel(b.OutDir, path)
			if err != nil {
				return fmt.Errorf("failed to get relative path for %s: %w", path, err)
			}
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk output directory %s: %w", b.OutDir, err)
	}

	privateKeyCache := map[string]*whisper.PrivateKey{}

	for _, p := range files {
		outPath := filepath.Join(b.root, strings.TrimSuffix(p, WHISPER_FILE_EXT))
		err := os.MkdirAll(filepath.Dir(outPath), 0o755)
		if err != nil {
			return fmt.Errorf("failed to create output directory for %s: %w", outPath, err)
		}

		output := getOutput(outPath)

		inPath := filepath.Join(b.OutDir, p)
		meta, input := getMeta(getInput(inPath, ""))

		var privateKey *whisper.PrivateKey
		if cached, ok := privateKeyCache[privateKeyPath]; ok {
			privateKey = cached
		} else {
			privateKey = getPrivate(true, false, privateKeyPath, meta)
			privateKeyCache[privateKeyPath] = privateKey
		}

		conf := whisper.Config{Private: privateKey}

		err = run(conf, input, output)
		if err != nil {
			if errors.Is(err, secure.ErrNotRecipient) {
				_, _ = fmt.Fprintf(os.Stderr, "[skip] not a recipient: %s\n", inPath)
				return nil
			}
			return fmt.Errorf("failed to decrypt file %s: %w", inPath, err)
		}

		_, _ = fmt.Fprintf(os.Stdout, "[decrypted] %s -> %s\n", inPath, outPath)
	}

	return nil
}

func (b *Batch) same(conf whisper.Config, inPath, outPath string) (bool, error) {
	hash := sha256.New()

	_, err := hash.Write([]byte{whisper.WireFormatVersion})
	if err != nil {
		return false, fmt.Errorf("failed to write version to hash: %w", err)
	}

	err = json.NewEncoder(hash).Encode(conf)
	if err != nil {
		return false, fmt.Errorf("failed to encode config for hashing: %w", err)
	}

	inFile, err := os.Open(inPath)
	if err != nil {
		return false, fmt.Errorf("failed to open input file %s: %w", inPath, err)
	}
	defer func() { _ = inFile.Close() }()

	_, err = io.Copy(hash, inFile)
	if err != nil {
		return false, fmt.Errorf("failed to hash input file %s: %w", inPath, err)
	}

	digest := hash.Sum(nil)

	digestPath := outPath + WHISPER_DIGEST_EXT

	defer func() {
		_ = os.WriteFile(digestPath, digest, 0o644)
	}()

	previousDigest, err := os.ReadFile(digestPath)
	if err != nil {
		return false, nil
	}

	return bytes.Equal(digest, previousDigest), nil
}
