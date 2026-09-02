package input

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/ulikunitz/xz"
)

// A valid single-block stream, built with the library rather than the tool so
// the test has no external dependency, plus the offsets a test needs to
// corrupt it precisely.
func validXZ(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(bytes.Repeat([]byte("firmware "), 512)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func checkBytes(b []byte) error {
	return checkXZDictionaries(bytes.NewReader(b), int64(len(b)))
}

func TestXZContainerCheckAcceptsWhatXZWrites(t *testing.T) {
	stream := validXZ(t)
	if err := checkBytes(stream); err != nil {
		t.Fatalf("a stream the library wrote was refused: %v", err)
	}
	// Two streams back to back, with the padding xz permits between them.
	two := append(append(append([]byte{}, stream...), 0, 0, 0, 0), stream...)
	if err := checkBytes(two); err != nil {
		t.Fatalf("two padded streams were refused: %v", err)
	}
	// An empty file has nothing to check.
	if err := checkBytes(nil); err != nil {
		t.Fatalf("an empty file was refused: %v", err)
	}
}

// Every way the container can lie is an error, never a panic and never a
// decode: the check runs on untrusted bytes before anything else does.
func TestXZContainerCheckRefusesMalformedStreams(t *testing.T) {
	stream := validXZ(t)
	n := len(stream)
	corrupt := func(mutate func(b []byte)) []byte {
		b := append([]byte{}, stream...)
		mutate(b)
		return b
	}

	// The index begins after the stream header and the blocks; its position
	// comes from the footer's backward size.
	indexLen := (int(stream[n-8]) | int(stream[n-7])<<8 | int(stream[n-6])<<16 | int(stream[n-5])<<24 + 1) * 4
	indexStart := n - 12 - indexLen

	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"too short to hold a stream", stream[:20], "too short"},
		{"index indicator where a block header belongs", corrupt(func(b []byte) { b[12] = 0x00 }), "index found"},
		{"filter properties past the block header", corrupt(func(b []byte) { b[12+3] = 0x7F }), "past the block header"},
		{"absurd block count", corrupt(func(b []byte) {
			// The count varint, made nine bytes of continuation.
			copy(b[indexStart+1:], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x7F})
		}), "blocks"},
		{"block larger than the stream", corrupt(func(b []byte) {
			// The first record's unpadded size, made enormous.
			copy(b[indexStart+2:], []byte{0xFF, 0xFF, 0xFF, 0x7F})
		}), "larger than the stream"},
		{"footer magic missing", corrupt(func(b []byte) { b[n-1] = 'X' }), "footer not found"},
		{"index runs past the stream start", corrupt(func(b []byte) { b[n-8], b[n-7] = 0xFF, 0x7F }), "past the start"},
		{"index too large to read", corrupt(func(b []byte) { b[n-5] = 0x7F }), "index of"},
		{"header magic missing", corrupt(func(b []byte) { b[0] = 0x00 }), "header not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkBytes(tt.input)
			if err == nil {
				t.Fatal("a corrupted stream passed the check")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestLZMA2DictionarySizeCodes(t *testing.T) {
	tests := []struct {
		code byte
		want int64
		ok   bool
	}{
		{0, 4 << 10, true},         // the smallest, 4 KiB
		{1, 6 << 10, true},         // odd codes are 1.5x the even one below
		{18, 2 << 20, true},        // 2 MiB
		{22, 8 << 20, true},        // 8 MiB, xz's default
		{28, 64 << 20, true},       // 64 MiB, xz -9
		{29, 96 << 20, true},       // the last size under the cap
		{30, 128 << 20, true},      // the cap itself
		{31, 192 << 20, true},      // over it
		{37, 1536 << 20, true},     // what --lzma2=dict=1536MiB writes
		{40, 0xFFFFFFFF, true},     // the largest the format allows
		{41, 0, false},             // undefined
		{0x3F, 0, false},           // undefined
		{0xC0 | 22, 8 << 20, true}, // the two high bits are reserved and ignored
	}
	for _, tt := range tests {
		got, ok := lzma2DictionarySize(tt.code)
		if got != tt.want || ok != tt.ok {
			t.Errorf("lzma2DictionarySize(%#x) = %d, %v; want %d, %v", tt.code, got, ok, tt.want, tt.ok)
		}
	}
}

func TestXZVarint(t *testing.T) {
	if v, n, err := xzVarint([]byte{0x7F}); err != nil || v != 127 || n != 1 {
		t.Errorf("one byte: %d, %d, %v", v, n, err)
	}
	if v, n, err := xzVarint([]byte{0x80, 0x01}); err != nil || v != 128 || n != 2 {
		t.Errorf("two bytes: %d, %d, %v", v, n, err)
	}
	// Nine continuation bytes with no terminator is malformed, not a loop.
	if _, _, err := xzVarint(bytes.Repeat([]byte{0xFF}, 12)); err == nil {
		t.Error("an unterminated integer was accepted")
	}
	if _, _, err := xzVarint(nil); err == nil {
		t.Error("an empty integer was accepted")
	}
}

// The block header check refuses the declaration, and the sentinel survives
// the wrapping so the CLI can name it.
func TestXZBlockHeaderRefusesALargeDictionary(t *testing.T) {
	stream := validXZ(t)
	// The block header starts after the 12-byte stream header; the LZMA2
	// properties byte is the last byte before its CRC in a header with no
	// sizes and one filter: [size][flags][id=0x21][propslen=1][props][crc x4].
	header := stream[12:]
	headerLen := (int(header[0]) + 1) * 4
	if header[1]&0xC0 != 0 || header[1]&0x03 != 0 || header[2] != 0x21 || header[3] != 1 {
		t.Skipf("the library wrote a block header shape this test does not expect: % x", header[:headerLen])
	}
	b := append([]byte{}, stream...)
	b[12+4] = 40 // the largest dictionary the format can declare
	err := checkBytes(b)
	if !errors.Is(err, ErrXZDictionary) {
		t.Fatalf("error = %v, want ErrXZDictionary", err)
	}
	b[12+4] = 41 // not a valid code at all
	if err := checkBytes(b); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("error = %v, want the invalid code refused", err)
	}
}
