// Package hibp implements privacy-preserving Pwned Passwords boundaries.
// Its bounded checker returns provider evidence and neutral risk signals,
// never a password acceptance decision.
package hibp

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
)

var (
	errMalformedRange     = errors.New("hibp: malformed range")
	errInvalidRangeLimits = errors.New("hibp: invalid range limits")
	errRangeUnavailable   = errors.New("hibp: range unavailable")
	errSensitive          = errors.New("hibp: sensitive serialization forbidden")
)

type rangeLimits struct {
	bytes int
	count uint32
}
type rangeEntry struct {
	suffix [35]byte
	count  uint32
}

// Parsed provider data stays private, immutable and distinct from bound evidence.
type rangeData struct{ entries []rangeEntry }

func (rangeData) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "hibp.rangeData(redacted)") }
func (rangeData) MarshalJSON() ([]byte, error) { return nil, errSensitive }
func (rangeData) MarshalText() ([]byte, error) { return nil, errSensitive }

// Parse the whole bounded stream, including a malformed tail after a match.
// A small fixed reader bounds row allocation; no complete body copy is made.
// CR is accepted only immediately before LF. A final LF is optional. Empty
// ranges and conflicting duplicates (including padding conflicts) fail closed.
func parseRange(ctx context.Context, source io.Reader, limits rangeLimits) (rangeData, error) {
	if ctx == nil || source == nil || limits.bytes < 1024 || limits.bytes > 2<<20 || limits.count == 0 || limits.count > 1_000_000_000 {
		return rangeData{}, errInvalidRangeLimits
	}
	if e := ctx.Err(); e != nil {
		return rangeData{}, e
	}
	reader := bufio.NewReaderSize(io.LimitReader(source, int64(limits.bytes)+1), 64)
	seen := make(map[[35]byte]uint32)
	var entries []rangeEntry
	total, rows := 0, 0
	fail := func(e error) (rangeData, error) {
		clear(entries)
		clear(seen)
		return rangeData{}, e
	}
	for {
		if e := ctx.Err(); e != nil {
			return fail(e)
		}
		line, readErr := reader.ReadSlice('\n')
		if e := ctx.Err(); e != nil {
			return fail(e)
		}
		total += len(line)
		if total > limits.bytes || readErr == bufio.ErrBufferFull {
			return fail(errMalformedRange)
		}
		if readErr != nil && readErr != io.EOF {
			return fail(errRangeUnavailable)
		}
		if len(line) == 0 && readErr == io.EOF {
			if rows == 0 {
				return fail(errMalformedRange)
			}
			break
		}
		if line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
		}
		// 35 hexadecimal suffix bytes, colon, and 1..10 decimal digits.
		if len(line) < 37 || len(line) > 46 || line[35] != ':' {
			return fail(errMalformedRange)
		}
		var suffix [35]byte
		for i, b := range line[:35] {
			if b >= 'a' && b <= 'f' {
				b -= 'a' - 'A'
			}
			if !(b >= '0' && b <= '9' || b >= 'A' && b <= 'F') {
				return fail(errMalformedRange)
			}
			suffix[i] = b
		}
		var count uint64
		for _, b := range line[36:] {
			if b < '0' || b > '9' {
				return fail(errMalformedRange)
			}
			count = count*10 + uint64(b-'0')
			if count > uint64(limits.count) {
				return fail(errMalformedRange)
			}
		}
		rows++
		// The shortest row occupies 38 bytes except an optional final newline.
		if rows > limits.bytes/38+1 {
			return fail(errMalformedRange)
		}
		if previous, exists := seen[suffix]; exists {
			if previous != uint32(count) {
				return fail(errMalformedRange)
			}
		} else {
			seen[suffix] = uint32(count)
			entries = append(entries, rangeEntry{suffix: suffix, count: uint32(count)})
		}
		if readErr == io.EOF {
			break
		}
	}
	clear(seen)
	if e := ctx.Err(); e != nil {
		return fail(e)
	}
	return rangeData{entries: entries}, nil
}

// Visit every validated entry regardless of the matching suffix's position.
// The count mask avoids a candidate-dependent branch or early success. Provider
// size still affects work; padding and HTTP privacy belong to the checker.
func (r rangeData) match(suffix [35]byte) uint32 {
	var count uint32
	for _, entry := range r.entries {
		mask := uint32(0) - uint32(subtle.ConstantTimeCompare(entry.suffix[:], suffix[:]))
		count |= entry.count & mask
	}
	return count
}
