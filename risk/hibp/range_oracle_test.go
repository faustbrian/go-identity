package hibp

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var rangeRowGrammar = regexp.MustCompile(`\A([0-9A-Fa-f]{35}):([0-9]{1,10})\z`)

// This oracle uses whole-input grammar and standard decimal parsing, independent
// of the production streaming scanner, canonicalization loop and accumulation.
func expectedRange(body string, budget int, maximum uint32) (map[string]uint32, bool) {
	if body == "" || len(body) > budget {
		return nil, false
	}
	lines := strings.Split(body, "\n")
	last := len(lines) - 1
	if lines[last] == "" {
		lines = lines[:last]
	}
	counts := make(map[string]uint32)
	for i, line := range lines {
		if i < last {
			line = strings.TrimSuffix(line, "\r")
		}
		match := rangeRowGrammar.FindStringSubmatch(line)
		if match == nil {
			return nil, false
		}
		count, err := strconv.ParseUint(match[2], 10, 32)
		if err != nil || count > uint64(maximum) {
			return nil, false
		}
		key := strings.ToUpper(match[1])
		if previous, exists := counts[key]; exists && previous != uint32(count) {
			return nil, false
		}
		counts[key] = uint32(count)
	}
	return counts, len(counts) != 0
}

func assertRangeOracle(t *testing.T, body string, budget int, maximum uint32) {
	t.Helper()
	want, valid := expectedRange(body, budget, maximum)
	got, err := parseRange(context.Background(), strings.NewReader(body), rangeLimits{bytes: budget, count: maximum})
	if (err == nil) != valid {
		t.Fatal("streaming parser disagreed with independent grammar")
	}
	if !valid {
		if !errors.Is(err, errMalformedRange) || len(got.entries) != 0 {
			t.Fatal("invalid complete range produced evidence")
		}
		return
	}
	if len(got.entries) != len(want) {
		t.Fatal("canonical unique row count changed")
	}
	seen := make(map[string]bool)
	for _, entry := range got.entries {
		key := string(entry.suffix[:])
		count, exists := want[key]
		if !exists || seen[key] || entry.count != count || got.match(entry.suffix) != count {
			t.Fatal("canonical suffix or breach count changed")
		}
		seen[key] = true
	}
	// At most budget/37 suffixes exist; this set has more distinct candidates.
	for n := uint64(0); ; n++ {
		key := strings.Repeat("0", 35-len(strconv.FormatUint(n, 16))) + strings.ToUpper(strconv.FormatUint(n, 16))
		if _, exists := want[key]; exists {
			continue
		}
		var absent [35]byte
		copy(absent[:], key)
		if got.match(absent) != 0 {
			t.Fatal("absent suffix became a breach")
		}
		break
	}
}

func TestRangeOracleBoundaryAndDuplicateSemantics(t *testing.T) {
	a, b := strings.Repeat("a", 35), strings.Repeat("B", 35)
	for _, body := range []string{
		a + ":0000000000\r\n", a + ":1000000000", a + ":00000000000\n",
		a + ":1000000001\n", a + ":1\n" + strings.ToUpper(a) + ":1\n" + b + ":0\n",
		b + ":0\n" + a + ":1\n", a + ":1\n" + strings.ToUpper(a) + ":2\n",
		a + ":1\r", a + ":1\r\r\n", a + ":1\n\n", a + ":1\nmalformed",
		strings.Repeat(b+":0\n", 110), "",
	} {
		assertRangeOracle(t, body, 4096, 1_000_000_000)
	}
}

type repeatingRangeReader struct {
	row  string
	read int
}

func (r *repeatingRangeReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.row[r.read%len(r.row)]
		r.read++
	}
	return len(p), nil
}

func TestRangeInfiniteValidRowsConsumeOnlyBoundedBytes(t *testing.T) {
	source := &repeatingRangeReader{row: strings.Repeat("A", 35) + ":1\n"}
	got, err := parseRange(context.Background(), source, rangeLimits{bytes: 1024, count: 1})
	if !errors.Is(err, errMalformedRange) || len(got.entries) != 0 || source.read != 1025 {
		t.Fatal("infinite provider escaped byte bound or exposed partial evidence")
	}
}
