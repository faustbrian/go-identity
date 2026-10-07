package valkey

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestBoundedResponseReaderPreservesCompleteRESP2Frames(t *testing.T) {
	frames := []string{"+OK\r\n", "-MOVED 1 private-endpoint\r\n", ":-123\r\n", "$-1\r\n", "*-1\r\n", "*0\r\n", "$4\r\na\r\nb\r\n", "*2\r\n$9\r\ncommitted\r\n$3\r\n123\r\n", "*2\r\n*1\r\n:1\r\n+ok\r\n"}
	wire := strings.Join(frames, "")
	reader := newBoundedResponseReader(strings.NewReader(wire))
	var got bytes.Buffer
	for {
		var small [3]byte
		n, err := reader.Read(small[:])
		got.Write(small[:n])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal("valid frame rejected", err)
		}
	}
	if got.String() != wire {
		t.Fatal("frame bytes changed")
	}
}

func TestBoundedResponseReaderRejectsHostileFramesBeforeForwarding(t *testing.T) {
	cases := []string{
		"$9007199254740991\r\n", "*9007199254740991\r\n", "$129\r\n", "*33\r\n", "$-2\r\n", "*-2\r\n", "$01\r\nx\r\n", ":9223372036854775808\r\n", ":-9223372036854775809\r\n", ":-0\r\n", "+" + strings.Repeat("x", 129) + "\r\n", "+x\ny\r\n", "$1\r\nx\nx", "$1\r\n", "*1\r\n", "%1\r\n", "!3\r\nERR\r\n", "_\r\n", "*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n+ok\r\n",
		"*32\r\n" + strings.Repeat("$128\r\n"+strings.Repeat("x", 128)+"\r\n", 32),
		"*32\r\n" + strings.Repeat("*2\r\n:1\r\n:2\r\n", 32),
		"*1\r\n*1\r\n*1\r\n*1\r\n*0\r\n",
		"*1\r\n*1\r\n*1\r\n*1\r\n*-1\r\n",
	}
	for i, wire := range cases {
		reader := newBoundedResponseReader(strings.NewReader(wire))
		var output [8192]byte
		n, err := reader.Read(output[:])
		if n != 0 || !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("case %d forwarded hostile frame: n=%d err=%v", i, n, err)
		}
		if n, err = reader.Read(output[:]); n != 0 || !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("case %d resumed poisoned stream", i)
		}
	}
}

type markedReadError struct{}

func (markedReadError) Read([]byte) (int, error) {
	return 0, errors.New("private-credential private-endpoint")
}

func TestBoundedResponseReaderIOAndZeroValues(t *testing.T) {
	for _, reader := range []*boundedResponseReader{nil, {}, newBoundedResponseReader(nil), newBoundedResponseReader(markedReadError{})} {
		var output [1]byte
		if n, err := reader.Read(output[:]); n != 0 || !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatal("invalid IO state admitted", n, err)
		}
	}
	reader := newBoundedResponseReader(strings.NewReader("+OK\r\n"))
	if n, err := reader.Read(nil); n != 0 || err != nil {
		t.Fatal("empty read consumed IO", n, err)
	}
	got, err := io.ReadAll(reader)
	if err != nil || string(got) != "+OK\r\n" {
		t.Fatal("empty read changed following frame", err)
	}
	reader = newBoundedResponseReader(markedReadError{})
	if strings.Contains(fmt.Sprintf("%+v", reader), "private-") {
		t.Fatal("reader formatting leaked input")
	}
	if _, err := json.Marshal(reader); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal("reader serialized", err)
	}
	if _, err := reader.MarshalText(); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal("reader text serialized", err)
	}
}

type stalledReader struct{}

func (stalledReader) Read([]byte) (int, error) { return 0, nil }

func TestBoundedResponseReaderBoundaryAndPartialIO(t *testing.T) {
	maximum := "$128\r\n" + strings.Repeat("x", 128) + "\r\n"
	exactFrame := "*31\r\n" + strings.Repeat(maximum, 30) + "$5\r\n12345\r\n"
	if len(exactFrame) != 4096 {
		t.Fatal("incorrect boundary fixture")
	}
	for _, wire := range []string{maximum, exactFrame, "*1\r\n*1\r\n*1\r\n*0\r\n", "+" + strings.Repeat("x", 128) + "\r\n", "*32\r\n" + strings.Repeat(":1\r\n", 32), ":-9223372036854775808\r\n", ":9223372036854775807\r\n"} {
		got, err := io.ReadAll(newBoundedResponseReader(strings.NewReader(wire)))
		if err != nil || string(got) != wire {
			t.Fatal("bounded valid frame rejected", err)
		}
	}
	got, err := io.ReadAll(newBoundedResponseReader(strings.NewReader("+OK\r\n$10\r\nshort")))
	if string(got) != "+OK\r\n" || !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal("partial frame escaped", err)
	}
	if got, err = io.ReadAll(newBoundedResponseReader(stalledReader{})); len(got) != 0 || !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal("stalled source not bounded", err)
	}
}

func FuzzBoundedResponseReader(f *testing.F) {
	for _, seed := range []string{"", "+OK\r\n", "$999999999999999\r\n", "*1\r\n$1\r\nx\r\n", "*1\r\n*1\r\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire string) {
		if len(wire) > 8192 {
			return
		}
		reader := newBoundedResponseReader(strings.NewReader(wire))
		var output [4096]byte
		for i := 0; i <= len(wire)+1; i++ {
			n, err := reader.Read(output[:])
			if n < 0 || n > len(output) {
				t.Fatal("invalid read bound")
			}
			if err != nil {
				return
			}
			if n == 0 {
				t.Fatal("no progress")
			}
		}
		t.Fatal("unbounded framing work")
	})
}
