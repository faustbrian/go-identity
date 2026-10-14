package valkey

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
)

// boundedResponseReader validates a complete RESP2 frame before forwarding its
// header to a client's allocating parser. Read-buffer size alone cannot protect
// that parser from attacker-declared lengths. This private profile excludes
// RESP3 pushes, caching and unbounded management/discovery replies.
//
// One connection reader owns all mutable state; concurrent Read is unsupported.
// Connection deadlines/cancellation and closing remain the connection owner's
// responsibility. Malformed/truncated IO poisons the stream permanently.
type boundedResponseReader struct {
	input               *bufio.Reader
	frame               [4096]byte
	used, offset, nodes int
	err                 error
}

func newBoundedResponseReader(input io.Reader) *boundedResponseReader {
	r := &boundedResponseReader{}
	if input == nil {
		r.err = ErrOutcomeUnknown
	} else {
		r.input = bufio.NewReaderSize(input, 4096)
	}
	return r
}

func (*boundedResponseReader) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "valkey.boundedResponseReader(redacted)")
}
func (*boundedResponseReader) MarshalJSON() ([]byte, error) { return nil, ErrOutcomeUnknown }
func (*boundedResponseReader) MarshalText() ([]byte, error) { return nil, ErrOutcomeUnknown }

func (r *boundedResponseReader) Read(p []byte) (int, error) {
	if r == nil {
		return 0, ErrOutcomeUnknown
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	if r.input == nil {
		return 0, ErrOutcomeUnknown
	}
	if r.offset == r.used {
		r.used, r.offset, r.nodes = 0, 0, 0
		if err := r.readFrame(0); err != nil {
			// Preserve clean end-of-stream only; never retain native diagnostics.
			r.err = ErrOutcomeUnknown
			if err == io.EOF && r.used == 0 {
				r.err = io.EOF
			}
			// Release the buffered IO error and rejected bytes. The owner closes
			// the connection; this reader neither retains diagnostics nor owns it.
			r.input = nil
			clear(r.frame[:])
			r.used, r.offset, r.nodes = 0, 0, 0
			return 0, r.err
		}
	}
	n := copy(p, r.frame[r.offset:r.used])
	r.offset += n
	return n, nil
}

func (r *boundedResponseReader) byte() (byte, error) {
	if r.used == len(r.frame) {
		return 0, ErrOutcomeUnknown
	}
	b, err := r.input.ReadByte()
	if err != nil {
		return 0, err
	}
	r.frame[r.used] = b
	r.used++
	return b, nil
}

func (r *boundedResponseReader) line() (string, error) {
	start := r.used
	for i := 0; i <= 128; i++ {
		b, err := r.byte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			return "", ErrOutcomeUnknown
		}
		if b == '\r' {
			if b, err = r.byte(); err != nil || b != '\n' {
				return "", ErrOutcomeUnknown
			}
			return string(r.frame[start : r.used-2]), nil
		}
	}
	return "", ErrOutcomeUnknown
}

func (r *boundedResponseReader) readFrame(depth int) error {
	if depth > 4 || r.nodes >= 64 {
		return ErrOutcomeUnknown
	}
	r.nodes++
	kind, err := r.byte()
	if err != nil {
		return err
	}
	if kind != '+' && kind != '-' && kind != ':' && kind != '$' && kind != '*' {
		return ErrOutcomeUnknown
	}
	value, err := r.line()
	if err != nil {
		return err
	}
	if kind == '+' || kind == '-' {
		return nil
	}
	// Canonical bounded integers precede any payload read or child recursion.
	if len(value) == 0 || len(value) > 20 {
		return ErrOutcomeUnknown
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || strconv.FormatInt(n, 10) != value {
		return ErrOutcomeUnknown
	}
	if kind == ':' {
		return nil
	}
	if kind == '*' && depth >= 4 {
		return ErrOutcomeUnknown
	}
	if n == -1 {
		return nil
	}
	if n < 0 {
		return ErrOutcomeUnknown
	}
	if kind == '*' {
		if n > 32 || n > int64(64-r.nodes) {
			return ErrOutcomeUnknown
		}
		for i := int64(0); i < n; i++ {
			if err := r.readFrame(depth + 1); err != nil {
				return err
			}
		}
		return nil
	}
	if n > 128 || n+2 > int64(len(r.frame)-r.used) {
		return ErrOutcomeUnknown
	}
	start := r.used
	for i := int64(0); i < n+2; i++ {
		if _, err := r.byte(); err != nil {
			return err
		}
	}
	if r.frame[start+int(n)] != '\r' || r.frame[start+int(n)+1] != '\n' {
		return ErrOutcomeUnknown
	}
	return nil
}
