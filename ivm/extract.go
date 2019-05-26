package ivm

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	// "encoding/xml"
	"io"
	"io/ioutil"
	"path/filepath"

	"github.com/beevik/etree"
)

func ExtractVulns(ioReader io.Reader) ([]string, error) {
	byteReader := bufio.NewReader(ioReader)

	// gzip.Reader prefers an io.ByteReader
	// https://golang.org/pkg/compress/gzip/#NewReader
	// bufio.Reader implements io.ByteReader and
	// improves disk reading efficiency for IVM
	// content file, which is ~440 MB
	gzipReader, err := gzip.NewReader(byteReader)
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	jars, err := extractJars(tarReader)
	if err != nil {
		return nil, err
	}

	vulns, err := extractVulns(jars)
	if err != nil {
		return nil, err
	}

	return vulns, nil
}

func extractJars(tarReader *tar.Reader) ([][]byte, error) {
	var jars [][]byte

	err := forEachTarEntry(tarReader, func(te tarEntry) error {
		if filepath.Base(te.header.Name) == `vulns.jar` {
			jar, err := ioutil.ReadAll(te.reader)
			if err != nil {
				return err
			}

			jars = append(jars, jar)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return jars, nil
}

func extractVulns(jars [][]byte) ([]string, error) {
	var vulns []string
	for _, jar := range jars {
		jarReader := bytes.NewReader(jar)

		zipReader, err := zip.NewReader(jarReader, int64(len(jar)))
		if err != nil {
			return nil, err
		}

		err = forEachZipEntry(zipReader, func(ze zipEntry) error {
			if filepath.Ext(ze.header.Name) != `.xml` {
				return nil
			}

			doc := etree.NewDocument()
			if _, err := doc.ReadFrom(ze.reader); err != nil {
				return err
			}

			vuln := doc.SelectElement("Vulnerability")
			for _, elem := range vuln.FindElements("//*") {
				path := elem.GetPath()
				vulns = append(vulns, path)
				switch path {
				case `/Vulnerability/severity`:
					vulns = append(vulns, path+`=`+elem.Text())
				default:

				}

				for _, attr := range elem.Attr {
					pathWithAttr := fmt.Sprintf("%s@%s", path, attr.Key)
					switch pathWithAttr {
					case `/Vulnerability/AlternateIds/id@name`,
						`/Vulnerability@version`:
						vulns = append(vulns, pathWithAttr+`=`+attr.Value)
					default:
						vulns = append(vulns, pathWithAttr)
					}
				}
			}

			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return vulns, nil
}

type tarEntry struct {
	header *tar.Header
	reader *tar.Reader
}

type handleTarEntry = func(te tarEntry) error

func forEachTarEntry(tarReader *tar.Reader, handle handleTarEntry) error {
	for {
		tarHeader, err := tarReader.Next()

		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		case tarHeader == nil:
			continue
		}

		if err := handle(tarEntry{tarHeader, tarReader}); err != nil {
			return err
		}
	}

	return nil
}

type zipEntry struct {
	header zip.FileHeader
	reader io.Reader
}

type handleZipEntry = func(ze zipEntry) error

func forEachZipEntry(zr *zip.Reader, handle handleZipEntry) error {
	for _, zf := range zr.File {
		r, err := zf.Open()
		if err != nil {
			return err
		}
		defer r.Close()

		err = handle(zipEntry{zf.FileHeader, r})
		if err != nil {
			return err
		}
	}

	return nil
}

// func decodeVuln(r io.Reader) (Vuln, error) {
// 	var vuln Vuln
// 	if err := xml.NewDecoder(r).Decode(&vuln); err != nil {
// 		return Vuln{}, err
// 	}

// 	return vuln, nil
// }
