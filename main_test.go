package main

import (
	"testing"

	"github.com/ysmood/got"
)

func Test_getPublicKeys(t *testing.T) {
	g := got.T(t)

	list := getPublicKeys([]string{"@ysmood:DI1NTE5"})

	g.Len(list, 1)
}
