//go:build cvss4oracle

// Cross-checks the CVSS v4.0 base-score computation against FIRST's reference
// calculator, run as JavaScript. Tagged out of the normal build: it downloads
// the reference implementation and needs Docker to run Node. Use
// `make test-cvss4-oracle` after changing cvss4.go or the lookup table.
//
// FIRST's implementation is the oracle. If the two disagree, it is right.

package match

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// referenceCommit pins the reference implementation. cvss4_lookup.go was
// transcribed from this commit and cvss4.go ported from it; checking against a
// moving target would prove nothing about either.
const referenceCommit = "c5b0d409ae9f57c44264c6ce5f27d89298e1d32a"

const nodeImage = "node:22-alpine"

var referenceFiles = []string{"cvss_lookup.js", "max_composed.js", "max_severity.js", "cvss_score.js", "metrics.js"}

// driver reads one vector per line and prints its score, using the reference
// implementation exactly as the calculator page does: every threat,
// environmental and supplemental metric left at X, which is what makes the
// result a base score.
const driver = `
const fs = require('fs');
for (const f of ['cvss_lookup.js','max_composed.js','max_severity.js','metrics.js','cvss_score.js']) {
  eval(fs.readFileSync('/work/' + f, 'utf8'));
}
const out = [];
for (const line of fs.readFileSync(0, 'utf8').split('\n')) {
  if (!line) continue;
  const selected = {};
  for (const key of Object.keys(expectedMetricOrder)) selected[key] = 'X';
  for (const part of line.split('/').slice(1)) {
    const [k, v] = part.split(':');
    selected[k] = v;
  }
  out.push(cvss_score(selected, cvssLookup_global, maxSeverity, macroVector(selected)).toFixed(1));
}
process.stdout.write(out.join('\n') + '\n');
`

// TestCVSS4BaseScoreAgainstReference scores every base vector there is --
// 4x2x2x3x3x3x3x3x3x3x3 = 104,976 of them -- both ways and compares. Exhaustive
// rather than sampled: the table is hand-assigned data, so a transcription slip
// would sit in one cell and a sample would probably miss it.
func TestCVSS4BaseScoreAgainstReference(t *testing.T) {
	requireDocker(t)
	work := fetchReference(t)

	vectors := allBaseVectors()
	var stdin bytes.Buffer
	for _, v := range vectors {
		stdin.WriteString(v)
		stdin.WriteByte('\n')
	}
	t.Logf("scoring %d vectors", len(vectors))

	if err := os.WriteFile(filepath.Join(work, "driver.js"), []byte(driver), 0o644); err != nil {
		t.Fatalf("write driver: %v", err)
	}

	cmd := exec.Command("docker", "run", "--rm", "-i", "-v", work+":/work", nodeImage, "node", "/work/driver.js")
	cmd.Stdin = &stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker run: %v: %s", err, stderr.String())
	}

	lines := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	if len(lines) != len(vectors) {
		t.Fatalf("reference returned %d scores for %d vectors", len(lines), len(vectors))
	}

	mismatches := 0
	for i, vector := range vectors {
		want, err := strconv.ParseFloat(strings.TrimSpace(lines[i]), 64)
		if err != nil {
			t.Fatalf("reference score %q for %s: %v", lines[i], vector, err)
		}
		got, ok := cvss4BaseScore(vector)
		if !ok {
			t.Fatalf("cvss4BaseScore(%s) rejected a valid vector", vector)
		}
		if got != want {
			mismatches++
			if mismatches <= 20 {
				t.Errorf("cvss4BaseScore(%s) = %.1f, reference says %.1f", vector, got, want)
			}
		}
	}
	t.Logf("%d vectors compared, %d mismatches", len(vectors), mismatches)
}

// allBaseVectors enumerates the whole base metric space.
func allBaseVectors() []string {
	values := [][]string{
		{"N", "A", "L", "P"}, // AV
		{"L", "H"},           // AC
		{"N", "P"},           // AT
		{"N", "L", "H"},      // PR
		{"N", "P", "A"},      // UI
		{"H", "L", "N"},      // VC
		{"H", "L", "N"},      // VI
		{"H", "L", "N"},      // VA
		{"H", "L", "N"},      // SC
		{"H", "L", "N"},      // SI
		{"H", "L", "N"},      // SA
	}

	vectors := []string{"CVSS:4.0"}
	for i, key := range cvss4BaseKeys {
		var next []string
		for _, prefix := range vectors {
			for _, value := range values[i] {
				next = append(next, fmt.Sprintf("%s/%s:%s", prefix, key, value))
			}
		}
		vectors = next
	}
	return vectors
}

// fetchReference downloads the pinned reference implementation into a temp
// directory the container can read.
func fetchReference(t *testing.T) string {
	t.Helper()
	// Not t.TempDir(): Docker needs a path it can bind-mount, and the test's
	// own cleanup would race the container on some setups.
	work, err := os.MkdirTemp("", "cvss4-reference-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(work) })

	for _, name := range referenceFiles {
		url := fmt.Sprintf("https://raw.githubusercontent.com/FIRSTdotorg/cvss-v4-calculator/%s/%s", referenceCommit, name)
		resp, err := http.Get(url)
		if err != nil {
			t.Skipf("cannot reach the reference implementation: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d, err %v", url, resp.StatusCode, err)
		}
		if err := os.WriteFile(filepath.Join(work, name), body, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return work
}
