package input

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ErrXZDictionary reports an xz stream declaring a dictionary fwscan will not
// allocate.
var ErrXZDictionary = errors.New("xz stream declares a dictionary larger than fwscan will allocate")

// checkXZDictionaries refuses a file any block of which declares an LZMA2
// dictionary above maxXZDictionary, before a byte of it is decoded.
//
// An xz block declares its dictionary size in one byte of filter properties,
// and the decoder allocates the whole dictionary when it reaches the block --
// the library's DictCap is a floor it grows past, not a ceiling. A 180-byte
// file declaring a 1.5 GiB dictionary therefore cost 1.5 GiB, and would have
// cost it during detection, which decodes only enough to sniff the payload.
// The declarations are read from the container instead. Every stream ends with
// an index naming each block's size, so the block headers can be found and
// read without decoding anything; a file may hold several streams back to
// back, so they are walked from the end.
func checkXZDictionaries(f io.ReaderAt, size int64) error {
	pos := size
	for streams := 0; pos > 0; streams++ {
		if streams >= maxXZStreams {
			return fmt.Errorf("%w: more than %d concatenated streams", ErrXZDictionary, maxXZStreams)
		}
		streamStart, err := checkXZStream(f, pos)
		if err != nil {
			return err
		}
		pos = streamStart
		// Streams may be separated by padding: whole multiples of four zero
		// bytes.
		for pos >= 4 {
			var pad [4]byte
			if _, err := f.ReadAt(pad[:], pos-4); err != nil {
				return fmt.Errorf("xz: %w", err)
			}
			if pad != [4]byte{} {
				break
			}
			pos -= 4
		}
	}
	return nil
}

const (
	xzStreamHeaderLen = 12
	xzStreamFooterLen = 12
	// maxXZIndex bounds the index read for one stream: a record is at most
	// eighteen bytes, so this is over three million blocks, which is not a
	// firmware image.
	maxXZIndex   = 64 << 20
	maxXZBlocks  = 1 << 20
	maxXZStreams = 1024
	// lzma2FilterID is the filter whose properties byte carries the dictionary
	// size. The other filters xz defines -- the BCJ converters and delta --
	// carry no dictionary.
	lzma2FilterID = 0x21
)

var (
	xzHeaderMagic = []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}
	xzFooterMagic = []byte{'Y', 'Z'}
)

// checkXZStream walks one stream whose last byte is at end, checks every block
// header it lists, and returns the offset the stream starts at.
func checkXZStream(f io.ReaderAt, end int64) (int64, error) {
	if end < xzStreamHeaderLen+xzStreamFooterLen {
		return 0, fmt.Errorf("xz: stream is too short")
	}

	// Footer: CRC32, backward size, flags, magic.
	var footer [xzStreamFooterLen]byte
	if _, err := f.ReadAt(footer[:], end-xzStreamFooterLen); err != nil {
		return 0, fmt.Errorf("xz: read stream footer: %w", err)
	}
	if string(footer[10:12]) != string(xzFooterMagic) {
		return 0, fmt.Errorf("xz: stream footer not found where the stream ends")
	}
	indexLen := (int64(binary.LittleEndian.Uint32(footer[4:8])) + 1) * 4
	if indexLen > maxXZIndex {
		return 0, fmt.Errorf("%w: index of %d bytes", ErrXZDictionary, indexLen)
	}
	indexStart := end - xzStreamFooterLen - indexLen
	if indexStart < xzStreamHeaderLen {
		return 0, fmt.Errorf("xz: index runs past the start of the stream")
	}

	index := make([]byte, indexLen)
	if _, err := f.ReadAt(index, indexStart); err != nil {
		return 0, fmt.Errorf("xz: read index: %w", err)
	}
	if index[0] != 0x00 {
		return 0, fmt.Errorf("xz: index indicator not found")
	}
	cursor := index[1:]
	count, n, err := xzVarint(cursor)
	if err != nil {
		return 0, err
	}
	if count > maxXZBlocks {
		return 0, fmt.Errorf("%w: %d blocks", ErrXZDictionary, count)
	}
	cursor = cursor[n:]

	// Block sizes, so the block headers can be found from the stream start.
	var blocksLen int64
	unpadded := make([]int64, 0, count)
	for range count {
		u, n, err := xzVarint(cursor)
		if err != nil {
			return 0, err
		}
		cursor = cursor[n:]
		if _, n, err = xzVarint(cursor); err != nil { // uncompressed size, unused
			return 0, err
		}
		cursor = cursor[n:]
		// A block cannot be larger than the file it sits in, so a size past
		// that is a lie rather than a value to convert.
		if u > uint64(indexStart) {
			return 0, fmt.Errorf("xz: index names a block larger than the stream")
		}
		padded := (int64(u) + 3) &^ 3 //nolint:gosec // bounded by indexStart above
		unpadded = append(unpadded, padded)
		blocksLen += padded
	}
	streamStart := indexStart - blocksLen - xzStreamHeaderLen
	if streamStart < 0 {
		return 0, fmt.Errorf("xz: blocks run past the start of the file")
	}
	var header [xzStreamHeaderLen]byte
	if _, err := f.ReadAt(header[:], streamStart); err != nil {
		return 0, fmt.Errorf("xz: read stream header: %w", err)
	}
	if string(header[:6]) != string(xzHeaderMagic) {
		return 0, fmt.Errorf("xz: stream header not found where the index says the stream starts")
	}

	block := streamStart + xzStreamHeaderLen
	for _, padded := range unpadded {
		if err := checkXZBlockHeader(f, block); err != nil {
			return 0, err
		}
		block += padded
	}
	return streamStart, nil
}

// checkXZBlockHeader reads one block header and refuses an LZMA2 filter whose
// declared dictionary is over the cap.
func checkXZBlockHeader(f io.ReaderAt, at int64) error {
	var first [1]byte
	if _, err := f.ReadAt(first[:], at); err != nil {
		return fmt.Errorf("xz: read block header: %w", err)
	}
	if first[0] == 0x00 {
		return fmt.Errorf("xz: index found where a block header was expected")
	}
	headerLen := (int(first[0]) + 1) * 4
	hdr := make([]byte, headerLen)
	if _, err := f.ReadAt(hdr, at); err != nil {
		return fmt.Errorf("xz: read block header: %w", err)
	}

	flags := hdr[1]
	cursor := hdr[2 : headerLen-4] // the trailing four bytes are the CRC
	if flags&0x40 != 0 {           // compressed size present
		_, n, err := xzVarint(cursor)
		if err != nil {
			return err
		}
		cursor = cursor[n:]
	}
	if flags&0x80 != 0 { // uncompressed size present
		_, n, err := xzVarint(cursor)
		if err != nil {
			return err
		}
		cursor = cursor[n:]
	}
	for range int(flags&0x03) + 1 {
		id, n, err := xzVarint(cursor)
		if err != nil {
			return err
		}
		cursor = cursor[n:]
		propsLen, n, err := xzVarint(cursor)
		if err != nil {
			return err
		}
		cursor = cursor[n:]
		if propsLen > uint64(len(cursor)) {
			return fmt.Errorf("xz: filter properties run past the block header")
		}
		props := cursor[:propsLen]
		cursor = cursor[propsLen:]
		if id != lzma2FilterID || len(props) != 1 {
			continue
		}
		dict, ok := lzma2DictionarySize(props[0])
		if !ok {
			return fmt.Errorf("xz: invalid LZMA2 dictionary size")
		}
		if dict > maxXZDictionary {
			return fmt.Errorf("%w: %d bytes declared, %d allowed", ErrXZDictionary, dict, int64(maxXZDictionary))
		}
	}
	return nil
}

// lzma2DictionarySize decodes the one-byte dictionary encoding the LZMA2
// filter uses: the low six bits are a size code, 40 meaning the largest.
func lzma2DictionarySize(b byte) (int64, bool) {
	bits := b & 0x3F
	switch {
	case bits > 40:
		return 0, false
	case bits == 40:
		return 0xFFFFFFFF, true
	default:
		return int64(2|(bits&1)) << (bits/2 + 11), true
	}
}

// xzVarint decodes xz's multibyte integer: seven bits a byte, low bits first,
// the high bit marking continuation, nine bytes at most.
func xzVarint(b []byte) (value uint64, n int, err error) {
	for i := 0; i < len(b) && i < 9; i++ {
		value |= uint64(b[i]&0x7F) << (7 * i)
		if b[i]&0x80 == 0 {
			return value, i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("xz: malformed integer")
}
