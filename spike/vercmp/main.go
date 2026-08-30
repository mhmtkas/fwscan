package main

import (
	"fmt"
	"os"
	"strings"

	debver "github.com/knqyf263/go-deb-version"
)

func main() {
	sc := os.Stdin
	buf := make([]byte, 1<<20)
	n, _ := sc.Read(buf)
	for _, line := range strings.Split(strings.TrimSpace(string(buf[:n])), "\n") {
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		a, err1 := debver.NewVersion(f[0])
		b, err2 := debver.NewVersion(f[1])
		if err1 != nil || err2 != nil {
			fmt.Printf("%s %s ERR\n", f[0], f[1])
			continue
		}
		var op string
		switch c := a.Compare(b); {
		case c < 0:
			op = "lt"
		case c > 0:
			op = "gt"
		default:
			op = "eq"
		}
		fmt.Printf("%s %s %s\n", f[0], f[1], op)
	}
}
