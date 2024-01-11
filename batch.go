package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	whisper "github.com/ysmood/whisper/lib"
	"github.com/ysmood/whisper/lib/secure"
	"golang.org/x/sync/errgroup"
)

type Batch struct {
	Groups map[string][]string `json:"groups"`
	Admins []string            `json:"admins"`
	Files  map[string][]string `json:"files"`
	OutDir string              `json:"outDir"`

	root string
}

func NewBatch(configPath string) (*Batch, error) {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	conf := Batch{}
	err = json.Unmarshal(b, &conf)
	if err != nil {
		return nil, err
	}

	conf.root = filepath.Dir(configPath)

	if conf.OutDir == "" {
		conf.OutDir = "vault"
	}

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
				return nil, err
			}
			members = append(members, ms...)
		} else {
			members = append(members, member)
		}
	}

	slices.Sort(members)

	return members, nil
}

func (b *Batch) ExpandGroups() (map[string][]string, error) {
	expanded := map[string][]string{}

	for k := range b.Groups {
		ms, err := b.GetMembers(k)
		if err != nil {
			return nil, err
		}
		expanded[k] = ms
	}

	return expanded, nil
}

func (b *Batch) ExpandFiles() (map[string][]string, error) { //nolint: gocognit
	files := map[string][]string{}
	groups, err := b.ExpandGroups()
	if err != nil {
		return nil, err
	}

	for p, members := range b.Files {
		expanded := []string{}
		members = append(members, b.Admins...)
		for _, member := range members {
			if strings.HasPrefix(member, "$") {
				if _, ok := groups[member]; !ok {
					return nil, fmt.Errorf("%w: %s", ErrGroupNotDefined, member)
				}

				expanded = append(expanded, groups[member]...)
			} else {
				expanded = append(expanded, member)
			}
		}

		slices.Sort(expanded)
		list := uniqueStrings(expanded)
		files[p] = list
	}

	expanded := map[string][]string{}
	for p, members := range files {
		p := filepath.FromSlash(p)

		stat, err := os.Stat(filepath.Join(b.root, p))
		if err != nil {
			return nil, err
		}

		if stat.IsDir() { //nolint: nestif
			err := filepath.WalkDir(filepath.Join(b.root, p), func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					return nil
				}

				path, err = filepath.Rel(b.root, path)
				if err != nil {
					return err
				}

				expanded[path] = append(expanded[path], members...)
				return nil
			})
			if err != nil {
				return nil, err
			}
		} else {
			expanded[p] = append(expanded[p], members...)
		}
	}

	return expanded, nil
}

func (b *Batch) Encrypt() error {
	files, err := b.ExpandFiles()
	if err != nil {
		return err
	}

	eg := errgroup.Group{}

	for p, members := range files {
		p := p
		members := members

		err = os.MkdirAll(filepath.Join(b.OutDir, filepath.Dir(p)), 0o755)
		if err != nil {
			return err
		}

		eg.Go(func() error {
			outPath := filepath.Join(b.OutDir, p+WHISPER_FILE_EXT)
			inPath := filepath.Join(b.root, p)
			input := getInput(inPath, "")
			output := getOutput(outPath)

			conf := whisper.Config{
				GzipLevel: 9,
				Public:    getPublicKeys(members),
			}

			same, err := b.sameRecipients(conf, outPath)
			if err != nil {
				return err
			}
			if same {
				fmt.Fprintf(os.Stderr, "[skip] recipients not changed: %s\n", inPath)
				return nil
			}

			err = run(conf, input, output)
			if err != nil {
				return err
			}

			fmt.Fprintf(os.Stdout, "[encrypted] %s -> %s\n", inPath, outPath)

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
				return err
			}
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return err
	}

	eg := errgroup.Group{}

	lock := sync.Mutex{}
	for _, p := range files {
		p := p

		eg.Go(func() error {
			outPath := filepath.Join(b.root, strings.TrimSuffix(p, WHISPER_FILE_EXT))
			err := os.MkdirAll(filepath.Dir(outPath), 0o755)
			if err != nil {
				return err
			}

			output := getOutput(outPath)

			inPath := filepath.Join(b.OutDir, p)
			meta, input := getMeta(getInput(inPath, ""))

			lock.Lock()
			privateKey := getPrivate(true, false, privateKeyPath, meta)
			lock.Unlock()

			conf := whisper.Config{Private: privateKey}

			err = run(conf, input, output)
			if errors.Is(err, secure.ErrNotRecipient) {
				fmt.Fprintf(os.Stderr, "[skip] not a recipient: %s\n", inPath)
				return nil
			}

			fmt.Fprintf(os.Stdout, "[decrypted] %s -> %s\n", inPath, outPath)

			return err
		})
	}

	return eg.Wait()
}

func (b *Batch) sameRecipients(conf whisper.Config, out string) (bool, error) {
	if _, err := os.Stat(out); os.IsNotExist(err) {
		return false, nil
	}

	input, err := os.Open(out)
	if err != nil {
		return false, err
	}

	defer func() { _ = input.Close() }()

	_, hashList, err := conf.Recipients()
	if err != nil {
		return false, err
	}

	meta, _ := getMeta(input)
	for _, h := range hashList {
		if _, has := meta.Recipients[string(h[:meta.HashSize()])]; !has {
			return false, nil
		}
	}

	return true, nil
}
