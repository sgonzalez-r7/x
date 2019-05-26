package main

import (
	"fmt"
	"log"
	"sort"
	// "strings"
	"os"
	"github.com/beevik/etree"

	fp "path/filepath"

	gdw "github.com/karrick/godirwalk"

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
	arg1 := os.Args[1]
	fmt.Println("Call with", os.Args[1:])

	// r, err := os.Open(file)
	// if err != nil {
	// 	log.Println("Error", err)
	// 	return
	// }

	files, err := paths(arg1)
	if err != nil {
		log.Println("Error", err)
	}

	count := make(map[string]int64)
	var path string


	for _, file := range files {

		doc := etree.NewDocument()
		if err := doc.ReadFromFile(file); err != nil {
			panic(err)
		}


		vuln := doc.SelectElement("Vulnerability")
		for _, child := range vuln.FindElements("//*") {
			for _, attr := range child.Attr {
				path = fmt.Sprintf("%s@%s\n", child.GetPath(), attr.Key)
				count[path]++
			}
		}
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

func paths(dir string) (paths []string, err error) {
	err = gdw.Walk(dir, &gdw.Options{
		Callback: func(path string, de *gdw.Dirent) error {
			if de.IsDir() || fp.Ext(path) != ".xml" {
				return nil
			}
			paths = append(paths, path)
			return nil
		},
		ErrorCallback: func(path string, err error) gdw.ErrorAction {
			log.Println("Error", err)
			return gdw.SkipNode
		},
		Unsorted: true,
	})
	if err != nil {
		return nil, err
	}

	return paths, nil
}









