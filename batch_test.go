package main

import (
	"path/filepath"
	"testing"

	"github.com/ysmood/got"
)

func TestBatchGroups(t *testing.T) {
	g := got.T(t)

	batch := Batch{
		Groups: map[string]Group{
			"$a": {"a", "b"},
			"$b": {"c", "$a"},
			"$c": {"$b"},
		},
	}
	list, err := batch.GetMembers("$c")
	g.E(err)

	g.Eq(list, []string{"a", "b", "c"})

	{
		batch := Batch{
			Groups: map[string]Group{
				"$a": {"$b"},
				"$b": {"$a"},
			},
		}

		_, err := batch.GetMembers("$a")
		g.Is(err, ErrCircularGroupReference)
	}
}

func TestBatchFiles(t *testing.T) {
	g := got.T(t)

	p := "tmp/hello.txt"

	g.WriteFile(filepath.FromSlash(p), "hello world!")

	batch := Batch{
		Files: map[string]Group{
			p: {"$c", "d"},
		},
		Groups: map[string]Group{
			"$a": {"a", "b"},
			"$b": {"c", "$a"},
			"$c": {"$b"},
		},
	}

	list, err := batch.ExpandFiles()
	g.E(err)

	g.Eq(list[filepath.FromSlash(p)], []string{"a", "b", "c", "d"})
}
