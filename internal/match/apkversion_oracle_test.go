//go:build apkoracle

// Cross-checks the apk version comparator against apk itself. Tagged out of the
// normal build: it needs Docker and pulls an Alpine image, which no unit test
// may depend on. Run it with `make test-apk-oracle` when apkversion.go changes.
//
// apk-tools is the oracle, not this code. If the two disagree, apk is right.

package match

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// alpineImage pins the image so the oracle is a fixed version of apk-tools,
// the one apkversion.go was ported from.
const alpineImage = "alpine:3.19"

// apkCorpus covers every branch of the token ladder: plain and dotted numbers,
// leading zeros, letter components, all four pre-suffixes and all five
// post-suffixes with and without a number, revisions, and the combinations
// Alpine actually ships (openssh is 9.3_p2-r0, busybox 1.36.1-r5).
//
// Nothing here starts with a dash: `apk version -c` would read it as a flag.
var apkCorpus = []string{
	"0", "1", "2", "1.0", "1.1", "1.9", "1.10", "2.0",
	"1.0.0", "1.0.1", "1.0.10",
	"1.00", "1.000", "1.01",
	"1.0a", "1.0b", "1.0z", "1.0a1", "1.0a2",
	"1.0_alpha", "1.0_alpha1", "1.0_alpha2",
	"1.0_beta", "1.0_beta1",
	"1.0_pre", "1.0_pre1",
	"1.0_rc", "1.0_rc1", "1.0_rc2",
	"1.0_cvs", "1.0_svn", "1.0_git", "1.0_git20230101",
	"1.0_hg", "1.0_p", "1.0_p1", "1.0_p2",
	"1.0-r0", "1.0-r1", "1.0-r2", "1.0-r10",
	"1.0_alpha1-r1", "1.0_p1-r0", "1.0a_rc1-r2",
	"1.0_alpha1_pre2", "1.0_git20230101_p1",
	"1.1.1o-r0", "1.1.1q-r0", "1.1.1w-r1", "1.1.1u-r0",
	"9.3_p1-r0", "9.3_p2-r0", "9.6_p1-r0",
	"1.36.1-r5", "2.14.4-r0", "3.19.0-r1",
	// Shapes that look malformed but parse: a trailing separator ends the
	// version, and a leading zero outside a dotted component is just a digit.
	"01", "1.0.", "1.0-r", "0.0", "10", "1.0.0.0",
}

// apkInvalidCorpus is checked for validity only; these do not parse, so there
// is no ordering to compare.
var apkInvalidCorpus = []string{
	"1.0_foo", "1.0-x", "1.0__1", "notaversion", "1.0+1", "1.0 2", "1:1.0",
	"1.0~rc1", "1.0-1",
}

func TestAPKVersionCompareAgainstAPK(t *testing.T) {
	requireDocker(t)

	var pairs [][2]string
	var stdin bytes.Buffer
	for _, a := range apkCorpus {
		for _, b := range apkCorpus {
			pairs = append(pairs, [2]string{a, b})
			fmt.Fprintf(&stdin, "%s %s\n", a, b)
		}
	}

	out := runInAlpine(t, `while read -r a b; do apk version -t "$a" "$b"; done`, stdin.String())
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != len(pairs) {
		t.Fatalf("oracle returned %d results for %d pairs", len(lines), len(pairs))
	}

	want := map[string]int{"<": -1, "=": 0, ">": 1}
	mismatches := 0
	for i, pair := range pairs {
		expected, ok := want[strings.TrimSpace(lines[i])]
		if !ok {
			t.Fatalf("apk version -t %q %q returned %q", pair[0], pair[1], lines[i])
		}
		if got := apkVersionCompare(pair[0], pair[1]); got != expected {
			mismatches++
			if mismatches <= 20 {
				t.Errorf("apkVersionCompare(%q, %q) = %d, apk says %d", pair[0], pair[1], got, expected)
			}
		}
	}
	t.Logf("%d pairs compared, %d mismatches", len(pairs), mismatches)
}

func TestAPKVersionValidAgainstAPK(t *testing.T) {
	requireDocker(t)

	all := append(append([]string{}, apkCorpus...), apkInvalidCorpus...)
	var stdin bytes.Buffer
	for _, v := range all {
		fmt.Fprintf(&stdin, "%s\n", v)
	}

	// `apk version -c` echoes the versions it rejects, so a line of output per
	// input keeps the results aligned with the inputs.
	out := runInAlpine(t, `while read -r v; do if apk version -c "$v" >/dev/null 2>&1; then echo valid; else echo invalid; fi; done`, stdin.String())
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != len(all) {
		t.Fatalf("oracle returned %d results for %d versions", len(lines), len(all))
	}

	for i, v := range all {
		want := strings.TrimSpace(lines[i]) == "valid"
		if got := apkVersionValid(v); got != want {
			t.Errorf("apkVersionValid(%q) = %v, apk says %v", v, got, want)
		}
	}
}

func runInAlpine(t *testing.T, script, stdin string) string {
	t.Helper()
	cmd := exec.Command("docker", "run", "--rm", "-i", alpineImage, "sh", "-c", script)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker run: %v: %s", err, stderr.String())
	}
	return stdout.String()
}
