package input

import (
	"errors"
	"fmt"
	"os"
)

// ErrUnsupportedFormat reports input fwscan cannot read. It is separate from an
// I/O failure so the CLI can tell the user which of the two happened.
var ErrUnsupportedFormat = errors.New("unsupported format")

// Format is what the input is.
type Format string

// The formats fwscan recognises. Handlers for tar and squashfs arrive in T5
// and T11; the constants exist now so detection has something to return.
const (
	FormatUnknown   Format = "unknown"
	FormatDirectory Format = "directory"
	FormatTar       Format = "tar"
	FormatSquashFS  Format = "squashfs"
)

func (f Format) String() string { return string(f) }

// Compression is the outer compression wrapping the input, if any. It is
// reported to the user in the terminal header, so "none" is a real value rather
// than an empty string.
type Compression string

// The outer compressions fwscan recognises, reported in the terminal header.
const (
	CompressionNone Compression = "none"
	CompressionGzip Compression = "gzip"
	CompressionXz   Compression = "xz"
	CompressionZstd Compression = "zstd"
	CompressionLZ4  Compression = "lz4"
)

func (c Compression) String() string { return string(c) }

// Detect identifies the input at path.
//
// Detection is by content, never by file extension: firmware build systems name
// things carelessly, and an lz4 image called .gz is common enough that the
// extension is worse than useless. Directories are the one case decided by a
// stat rather than by bytes.
func Detect(path string) (Format, Compression, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return FormatUnknown, CompressionNone, fmt.Errorf("no such path: %s", path)
		}
		return FormatUnknown, CompressionNone, fmt.Errorf("cannot read %s: %w", path, err)
	}
	if info.IsDir() {
		return FormatDirectory, CompressionNone, nil
	}
	// Magic-byte detection for archives and images lands in T5 and T11. Until
	// then a regular file is honestly reported as unrecognised rather than
	// guessed at.
	return FormatUnknown, CompressionNone, nil
}
