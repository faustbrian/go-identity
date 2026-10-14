package hibp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestRangePreservesCountsAndRejectsMalformedTail(t *testing.T) {
	a, b := strings.Repeat("A", 35), strings.Repeat("B", 35)
	limits := rangeLimits{bytes: 1024, count: 1_000_000_000}
	r, err := parseRange(context.Background(), strings.NewReader(a+":17\r\n"+strings.ToLower(a)+":17\n"+b+":0\n"), limits)
	if err != nil || len(r.entries) != 2 {
		t.Fatal("complete valid range rejected")
	}
	var target [35]byte
	copy(target[:], a)
	if r.match(target) != 17 {
		t.Fatal("matched prevalence lost")
	}
	copy(target[:], b)
	if r.match(target) != 0 {
		t.Fatal("padding became a breach")
	}
	for _, body := range []string{
		"", a + ":", a + ":-1", a + ":+1", a + ": 1", a + ":1 ", a + ":1:2",
		a[:34] + ":1", a + "A:1", a[:34] + "G:1", a + ":1\r", a + ":1\r\r\n",
		a + ":1\n\n", a + ":1000000001", a + ":99999999999999999999",
		a + ":17\n" + a + ":18", a + ":17\n" + a + ":0", a + ":17\nmalformed",
	} {
		result, e := parseRange(context.Background(), strings.NewReader(body), limits)
		if !errors.Is(e, errMalformedRange) || len(result.entries) != 0 {
			t.Fatal("malformed body exposed usable evidence")
		}
	}
}

func TestRangeBoundsAndFailures(t *testing.T) {
	row := strings.Repeat("C", 35) + ":1000000000"
	limits := rangeLimits{bytes: 1024, count: 1_000_000_000}
	for _, ending := range []string{"", "\n", "\r\n"} {
		if _, e := parseRange(context.Background(), strings.NewReader(row+ending), limits); e != nil {
			t.Fatal("legal last row rejected")
		}
	}
	for _, l := range []rangeLimits{{}, {bytes: 1023, count: 1}, {bytes: 2<<20 + 1, count: 1}, {bytes: 1024}, {bytes: 1024, count: 1_000_000_001}} {
		if _, e := parseRange(context.Background(), strings.NewReader(row), l); !errors.Is(e, errInvalidRangeLimits) {
			t.Fatal("invalid bounds accepted")
		}
	}
	if _, e := parseRange(nil, strings.NewReader(row), limits); e == nil {
		t.Fatal("nil context accepted")
	}
	if _, e := parseRange(context.Background(), nil, limits); e == nil {
		t.Fatal("nil reader accepted")
	}
	if _, e := parseRange(context.Background(), strings.NewReader(strings.Repeat(row+"\n", 30)), limits); !errors.Is(e, errMalformedRange) {
		t.Fatal("oversized body accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := parseRange(ctx, strings.NewReader(row), limits); !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	if r, e := parseRange(context.Background(), &brokenRangeReader{data: []byte(row + "\n")}, limits); e == nil || len(r.entries) != 0 {
		t.Fatal("partial read exposed evidence")
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", rangeData{}, rangeData{}, rangeData{}), "entries") {
		t.Fatal("range diagnostics not redacted")
	}
}

func TestRangeExactByteBoundAndWholeScan(t *testing.T) {
	a, b := strings.Repeat("A", 35), strings.Repeat("B", 35)
	// Twenty-six 38-byte rows plus one 36-byte suffix/colon and a one-byte
	// count produce 1025 bytes: replace the final row's LF with EOF for 1024.
	body := strings.Repeat(a+":1\n", 26) + b + ":1"
	limit := len(body)
	if limit != 1025 {
		t.Fatal("unexpected synthetic body size")
	}
	// Add leading zeros to select an exact, legal supported bound.
	body = strings.Repeat(a+":1\n", 25) + b + ":0000000001\n" + a + ":1"
	limit = len(body)
	for _, budget := range []int{limit, limit + 1} {
		if _, e := parseRange(context.Background(), strings.NewReader(body), rangeLimits{bytes: budget, count: 1}); e != nil {
			t.Fatal("body at limit rejected")
		}
	}
	if _, e := parseRange(context.Background(), strings.NewReader(body), rangeLimits{bytes: limit - 1, count: 1}); !errors.Is(e, errMalformedRange) {
		t.Fatal("body beyond limit accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	if r, e := parseRange(ctx, &cancelRangeReader{cancel: cancel, body: strings.NewReader(a + ":1\n")}, rangeLimits{bytes: 1024, count: 1}); !errors.Is(e, context.Canceled) || len(r.entries) != 0 {
		t.Fatal("cancel during input exposed evidence")
	}
	for _, body := range []string{a + ":1\n" + b + ":2\n", b + ":2\n" + a + ":1\n"} {
		r, e := parseRange(context.Background(), strings.NewReader(body), rangeLimits{bytes: 1024, count: 2})
		var target [35]byte
		copy(target[:], a)
		if e != nil || r.match(target) != 1 {
			t.Fatal("matching position changed count")
		}
		copy(target[:], strings.Repeat("F", 35))
		if r.match(target) != 0 {
			t.Fatal("absence became match")
		}
	}
}

type cancelRangeReader struct {
	cancel context.CancelFunc
	body   io.Reader
}

func (r *cancelRangeReader) Read(b []byte) (int, error) {
	n, e := r.body.Read(b)
	r.cancel()
	return n, e
}

func BenchmarkRangeBounded(b *testing.B) {
	for _, name := range []string{"unique", "duplicate"} {
		b.Run(name, func(b *testing.B) {
			var corpus strings.Builder
			for i := 0; i < 1024; i++ {
				suffix := i
				if name == "duplicate" {
					suffix = 0
				}
				fmt.Fprintf(&corpus, "%035X:1\n", suffix)
			}
			body := corpus.String()
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				if _, err := parseRange(context.Background(), strings.NewReader(body), rangeLimits{bytes: 1 << 20, count: 1_000_000_000}); err != nil {
					b.Fatal("range failed")
				}
			}
		})
	}
}

type brokenRangeReader struct{ data []byte }

func (r *brokenRangeReader) Read(b []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(b, r.data)
	r.data = r.data[n:]
	return n, nil
}

func FuzzRange(f *testing.F) {
	f.Add(strings.Repeat("A", 35) + ":1\r\n")
	f.Add(strings.Repeat("B", 35) + ":0\n")
	f.Add(strings.Repeat("a", 35) + ":1000000000")
	f.Add(strings.Repeat("A", 35) + ":00000000000\n")
	f.Add(strings.Repeat("A", 35) + ":1\n" + strings.Repeat("a", 35) + ":2\n")
	f.Add(":invalid")
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 4097 {
			t.Skip()
		}
		assertRangeOracle(t, body, 4096, 1_000_000_000)
	})
}
