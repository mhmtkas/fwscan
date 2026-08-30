// Command dpkgpoc is the T0.2 throwaway proof of concept: parse a dpkg status
// file into {name, version, arch} and print it for comparison against the
// dpkg-query oracle. Stdlib only, no module — run it with `go run`.
//
// This code is not meant to survive into Phase 1; T3 reimplements it properly.
// What must survive is the evidence that the parsing rules below are correct.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type pkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

// parse reads RFC-822-style stanzas separated by blank lines. Continuation
// lines (those starting with a space or tab) belong to the previous field and
// must not be mistaken for new fields or for a stanza boundary — that is the
// trap multi-line Description fields set.
func parse(r *os.File) ([]pkg, error) {
	var (
		out     []pkg
		fields  = map[string]string{}
		lastKey string
	)

	flush := func() {
		if len(fields) == 0 {
			return
		}
		// Only packages actually installed count. Any other Status
		// (deinstall, config-files, half-installed) is not present on disk.
		if fields["Status"] == "install ok installed" {
			out = append(out, pkg{
				Name:    fields["Package"],
				Version: fields["Version"],
				Arch:    fields["Architecture"],
			})
		}
		fields = map[string]string{}
		lastKey = ""
	}

	sc := bufio.NewScanner(r)
	// dpkg lines are short, but a hostile file could hand us a huge one; the
	// real cataloger will bound this properly. 1 MiB is plenty here.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case line[0] == ' ' || line[0] == '\t':
			if lastKey != "" {
				fields[lastKey] += "\n" + strings.TrimSpace(line)
			}
		default:
			key, val, ok := strings.Cut(line, ":")
			if !ok {
				continue // malformed line, skip rather than abort
			}
			lastKey = key
			fields[key] = strings.TrimSpace(val)
		}
	}
	flush() // a file need not end with a blank line
	return out, sc.Err()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dpkgpoc <status-file> [--oracle-format]")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()

	pkgs, err := parse(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })

	// --oracle-format prints exactly what `dpkg-query -W -f='${Package} ${Version}\n'`
	// prints, so the two can be diffed byte for byte.
	if len(os.Args) > 2 && os.Args[2] == "--oracle-format" {
		w := bufio.NewWriter(os.Stdout)
		defer w.Flush()
		for _, p := range pkgs {
			fmt.Fprintf(w, "%s %s\n", p.Name, p.Version)
		}
		return
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(pkgs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
