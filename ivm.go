package main

import (
	"fmt"
	"log"
	"sort"
	"os"

	"github.com/sgonzalez-r7/x/ivm"

	"github.com/davecgh/go-spew/spew"
)

var (
	scs spew.ConfigState = spew.ConfigState{
		Indent:                  "  ",
		DisableMethods:          true,
		DisablePointerAddresses: true,
	}
)

func main() {
	if len(os.Args[1:]) != 1 {
		fmt.Println("Usage: go run ivm.go <tgz>")
		return
	}
	tgz := os.Args[1]
	fmt.Println("called with", os.Args[1:])

	ioReader, err := os.Open(tgz)
	if err != nil {
		log.Println("Error", err)
		return
	}

	// ExtractVulns expects an io.Reader
	// reading from a .tgz file
	vulns, err := ivm.ExtractVulns(ioReader)
	if err != nil {
		log.Println("Error", err)
		return
	}

	count := make(map[string]int64)
	for _, xpath := range vulns {
		count[xpath]++
	}

	keys := make([]string, 0, len(count))
	for k := range count {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, k := range keys {
		fmt.Printf("%d %s\n", count[k], k)
	}
}
