package valkey

import (
	"bytes"
	"io"
	"strconv"
)

// This is a closed AUTH/HELLO/EVAL wire profile, not a general-purpose client.
// Count and byte bounds are established before request allocation. Commands
// are binary-safe; a partial socket write continues that same frame, never
// retries a command. No callback or background worker owns connection IO.
func encodeNativeRequests(requests [][]string) ([]byte, error) {
	if len(requests) < 1 || len(requests) > 2 {
		return nil, ErrOutcomeUnknown
	}
	size := 0
	for _, fields := range requests {
		if len(fields) < 1 || len(fields) > 64 {
			return nil, ErrOutcomeUnknown
		}
		size += len(strconv.Itoa(len(fields))) + 3
		for _, field := range fields {
			if len(field) > 8192 {
				return nil, ErrOutcomeUnknown
			}
			size += len(strconv.Itoa(len(field))) + len(field) + 5
			if size > 32768 {
				return nil, ErrOutcomeUnknown
			}
		}
	}
	wire := make([]byte, 0, size)
	for _, fields := range requests {
		wire = append(wire, '*')
		wire = strconv.AppendInt(wire, int64(len(fields)), 10)
		wire = append(wire, '\r', '\n')
		for _, field := range fields {
			wire = append(wire, '$')
			wire = strconv.AppendInt(wire, int64(len(field)), 10)
			wire = append(wire, '\r', '\n')
			wire = append(wire, field...)
			wire = append(wire, '\r', '\n')
		}
	}
	return wire, nil
}

func writeNativeRequest(w io.Writer, wire []byte) error {
	for len(wire) != 0 {
		n, err := w.Write(wire)
		if err != nil || n <= 0 || n > len(wire) {
			return ErrOutcomeUnknown
		}
		wire = wire[n:]
	}
	return nil
}

// Read buffers are at the complete-frame maximum. The framing owner validates
// the whole frame before returning any bytes, including startup metadata.
func readNativeFrame(r *boundedResponseReader) ([]byte, error) {
	var frame [4096]byte
	n, err := r.Read(frame[:])
	if err != nil || n == 0 {
		return nil, ErrOutcomeUnknown
	}
	return frame[:n], nil
}

func nativeHeader(frame []byte) (byte, int, []byte, error) {
	if len(frame) < 3 {
		return 0, 0, nil, ErrOutcomeUnknown
	}
	line, rest, found := bytes.Cut(frame[1:], []byte("\r\n"))
	if !found {
		return 0, 0, nil, ErrOutcomeUnknown
	}
	n, err := strconv.Atoi(string(line))
	if err != nil || strconv.Itoa(n) != string(line) {
		return 0, 0, nil, ErrOutcomeUnknown
	}
	return frame[0], n, rest, nil
}

func nativeString(frame []byte) (string, []byte, error) {
	if len(frame) < 3 {
		return "", nil, ErrOutcomeUnknown
	}
	if frame[0] == '+' {
		value, rest, found := bytes.Cut(frame[1:], []byte("\r\n"))
		if !found || len(value) > 128 {
			return "", nil, ErrOutcomeUnknown
		}
		return string(value), rest, nil
	}
	kind, n, rest, err := nativeHeader(frame)
	if err != nil || kind != '$' || n < 0 || n > 128 || len(rest) < n+2 || string(rest[n:n+2]) != "\r\n" {
		return "", nil, ErrOutcomeUnknown
	}
	return string(rest[:n]), rest[n+2:], nil
}

func nativeStringArray(frame []byte) ([]string, error) {
	kind, n, rest, err := nativeHeader(frame)
	if err != nil || kind != '*' || n < 2 || n > 19 {
		return nil, ErrOutcomeUnknown
	}
	values := make([]string, n)
	for i := range values {
		values[i], rest, err = nativeString(rest)
		if err != nil {
			return nil, ErrOutcomeUnknown
		}
	}
	if len(rest) != 0 {
		return nil, ErrOutcomeUnknown
	}
	return values, nil
}

// HELLO 2 must confirm RESP2 and standalone operation. Metadata is not health
// authority. Duplicate keys and incomplete/contradictory startup fail closed.
func nativeHello(frame []byte) bool {
	kind, n, rest, err := nativeHeader(frame)
	if err != nil || kind != '*' || n < 4 || n > 32 || n%2 != 0 {
		return false
	}
	var seen [16]string
	proto, mode := false, false
	for i := 0; i < n/2; i++ {
		key, next, keyErr := nativeString(rest)
		if keyErr != nil || key == "" {
			return false
		}
		for _, prior := range seen[:i] {
			if key == prior {
				return false
			}
		}
		seen[i] = key
		rest = next
		if key == "proto" {
			k, value, _, e := nativeHeader(rest)
			if e != nil || k != ':' || value != 2 {
				return false
			}
			proto = true
		}
		if key == "mode" {
			value, _, e := nativeString(rest)
			if e != nil || value != "standalone" {
				return false
			}
			mode = true
		}
		rest, err = nativeValueRest(rest, 0)
		if err != nil {
			return false
		}
	}
	return proto && mode && len(rest) == 0
}

// Startup's bounded HELLO metadata includes integers and nested module arrays.
// Skip only validated RESP2 value types, retaining no native diagnostic data.
func nativeValueRest(frame []byte, depth int) ([]byte, error) {
	if depth > 4 || len(frame) < 3 {
		return nil, ErrOutcomeUnknown
	}
	if frame[0] == '+' || frame[0] == '$' {
		_, rest, err := nativeString(frame)
		return rest, err
	}
	kind, n, rest, err := nativeHeader(frame)
	if err != nil {
		return nil, ErrOutcomeUnknown
	}
	if kind == ':' {
		return rest, nil
	}
	if kind != '*' || n < 0 || n > 32 {
		return nil, ErrOutcomeUnknown
	}
	for range n {
		rest, err = nativeValueRest(rest, depth+1)
		if err != nil {
			return nil, err
		}
	}
	return rest, nil
}
