package input

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
)

// Magic numbers, all read off files produced during the spike rather than
// quoted from documentation (spike/NOTES.md T0.4).
var (
	magicGzip     = []byte{0x1F, 0x8B}
	magicXz       = []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}
	magicZstd     = []byte{0x28, 0xB5, 0x2F, 0xFD}
	magicLZ4      = []byte{0x04, 0x22, 0x4D, 0x18}
	magicSquashFS = []byte{'h', 's', 'q', 's'}
	// tar is the odd one out: it has no magic at offset 0. "ustar" sits at
	// offset 257, inside the first header block.
	magicTar       = []byte{'u', 's', 't', 'a', 'r'}
	magicTarOffset = 257
)

// peekLen is how much of the file the detector reads. It has to reach past the
// tar magic at offset 257.
const peekLen = 512

// detectCompression identifies the outer compression from a file's leading
// bytes. Extensions are ignored entirely: an lz4 image named .gz is a real
// thing in firmware build output.
func detectCompression(header []byte) Compression {
	switch {
	case bytes.HasPrefix(header, magicGzip):
		return CompressionGzip
	case bytes.HasPrefix(header, magicXz):
		return CompressionXz
	case bytes.HasPrefix(header, magicZstd):
		return CompressionZstd
	case bytes.HasPrefix(header, magicLZ4):
		return CompressionLZ4
	default:
		return CompressionNone
	}
}

// detectFormat identifies an uncompressed payload from its leading bytes.
func detectFormat(header []byte) Format {
	switch {
	case bytes.HasPrefix(header, magicSquashFS):
		return FormatSquashFS
	case len(header) >= magicTarOffset+len(magicTar) &&
		bytes.HasPrefix(header[magicTarOffset:], magicTar):
		return FormatTar
	default:
		return FormatUnknown
	}
}

// decompress wraps r in the reader for the given compression. The returned
// closer releases the decompressor's own resources; it does not close r.
func decompress(r io.Reader, c Compression) (io.Reader, io.Closer, error) {
	switch c {
	case CompressionNone:
		return r, nopCloser{}, nil
	case CompressionGzip:
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, nil, fmt.Errorf("gzip: %w", err)
		}
		return zr, zr, nil
	case CompressionXz:
		xr, err := xz.NewReader(r)
		if err != nil {
			return nil, nil, fmt.Errorf("xz: %w", err)
		}
		return xr, nopCloser{}, nil
	case CompressionZstd:
		zr, err := zstd.NewReader(r)
		if err != nil {
			return nil, nil, fmt.Errorf("zstd: %w", err)
		}
		return zr.IOReadCloser(), zr.IOReadCloser(), nil
	case CompressionLZ4:
		return lz4.NewReader(r), nopCloser{}, nil
	default:
		return nil, nil, fmt.Errorf("%w: compression %s", ErrUnsupportedFormat, c)
	}
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }
