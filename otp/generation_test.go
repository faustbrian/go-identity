package otp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func profileSpec() CodeProfileSpec {
	return CodeProfileSpec{Purpose: PurposeSignin, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: time.Minute, MaximumSends: 5, Attempts: 5, Replacement: ReplacePrevious}
}

func mustProfile(t *testing.T) CodeProfile {
	t.Helper()
	p, err := NewCodeProfile(profileSpec())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCodeProfileBounds(t *testing.T) {
	s := profileSpec()
	for _, purpose := range []Purpose{PurposeSignin, PurposeEmailVerification, PurposePasswordReset, PurposeEmailChange, PurposeMFA, PurposeStepUp} {
		s.Purpose = purpose
		p, err := NewCodeProfile(s)
		if err != nil {
			t.Fatal("required purpose rejected")
		}
		got, err := p.Bindings()
		if err != nil || got != s {
			t.Fatal("profile changed")
		}
	}
	invalid := []func(*CodeProfileSpec){
		func(s *CodeProfileSpec) { s.Purpose = "" }, func(s *CodeProfileSpec) { s.Purpose = "custom" },
		func(s *CodeProfileSpec) { s.Alphabet = "" }, func(s *CodeProfileSpec) { s.Alphabet = "0" },
		func(s *CodeProfileSpec) { s.Alphabet = "01234567890" }, func(s *CodeProfileSpec) { s.Alphabet = "012345678\n" },
		func(s *CodeProfileSpec) { s.Alphabet = "012345678é" }, func(s *CodeProfileSpec) { s.Alphabet = strings.Repeat("a", 95) },
		func(s *CodeProfileSpec) { s.Length = 3 }, func(s *CodeProfileSpec) { s.Length = 129 },
		func(s *CodeProfileSpec) { s.Alphabet = "01"; s.Length = 19 },
		func(s *CodeProfileSpec) { s.TTL = 30*time.Second - 1 }, func(s *CodeProfileSpec) { s.TTL = 10*time.Minute + 1 },
		func(s *CodeProfileSpec) { s.ResendInterval = 30*time.Second - 1 }, func(s *CodeProfileSpec) { s.ResendInterval = 10*time.Minute + 1 },
		func(s *CodeProfileSpec) { s.MaximumSends = 0 }, func(s *CodeProfileSpec) { s.MaximumSends = 11 },
		func(s *CodeProfileSpec) { s.Attempts = 0 }, func(s *CodeProfileSpec) { s.Attempts = 11 },
		func(s *CodeProfileSpec) { s.Replacement = 0 }, func(s *CodeProfileSpec) { s.Replacement = 99 },
	}
	for i, mutate := range invalid {
		s := profileSpec()
		mutate(&s)
		if p, err := NewCodeProfile(s); !errors.Is(err, ErrInvalidProfile) || p != (CodeProfile{}) {
			t.Fatalf("invalid profile %d admitted", i)
		}
	}
	if _, err := (CodeProfile{}).Bindings(); !errors.Is(err, ErrInvalidProfile) {
		t.Fatal("zero profile accepted")
	}
	for _, length := range []int{20, 128} {
		s := profileSpec()
		s.Alphabet = "01"
		s.Length = length
		s.Replacement = RetainPrevious
		if _, err := NewCodeProfile(s); err != nil {
			t.Fatal("valid binary profile rejected")
		}
	}
}

func TestGenerateRejectsBiasedTailAndClearsBorrowedCode(t *testing.T) {
	p := mustProfile(t)
	// 250..255 must be rejected for a ten-symbol alphabet, not mapped modulo 10.
	input := []byte{255, 250, 249, 0, 1, 2, 3, 4}
	var borrowed []byte
	err := p.generate(context.Background(), bytes.NewReader(input), func(_ context.Context, code []byte) error {
		if string(code) != "901234" {
			t.Fatal("biased tail admitted or alphabet changed")
		}
		borrowed = code
		return nil
	})
	if err != nil || len(borrowed) != 6 || !bytes.Equal(borrowed, make([]byte, 6)) {
		t.Fatal("borrowed code not cleared", err)
	}
}

func TestSamplerEveryByteAndBoundedDraws(t *testing.T) {
	p := mustProfile(t)
	var frequencies [10]int
	for value := 0; value < 256; value++ {
		calls := 0
		reader := &countedEntropy{reader: bytes.NewReader(bytes.Repeat([]byte{byte(value)}, 10000))}
		err := p.generate(context.Background(), reader, func(_ context.Context, b []byte) error {
			calls++
			if !bytes.Equal(b, bytes.Repeat([]byte{byte('0' + value%10)}, 6)) {
				t.Fatal("wrong mapping")
			}
			return nil
		})
		if value < 250 {
			if err != nil || calls != 1 || reader.reads != 6 {
				t.Fatal("uniform accepted bucket failed")
			}
			frequencies[value%10]++
		} else if !errors.Is(err, ErrGenerationUnavailable) || calls != 0 || reader.reads != 6*32 {
			t.Fatal("rejected tail unbounded or disclosed code")
		}
	}
	for _, n := range frequencies {
		if n != 25 {
			t.Fatal("unequal source buckets")
		}
	}
}

type countedEntropy struct {
	reader io.Reader
	reads  int
}

func (r *countedEntropy) Read(b []byte) (int, error) { r.reads++; return r.reader.Read(b) }

type cancellingEntropy struct{ cancel context.CancelFunc }

func (r cancellingEntropy) Read(b []byte) (int, error) { r.cancel(); b[0] = 0; return 1, nil }

func TestEntropyCancellationAndBoundedCallbackContext(t *testing.T) {
	p := mustProfile(t)
	ctx, cancel := context.WithCancel(context.Background())
	called := false
	err := p.generate(ctx, cancellingEntropy{cancel}, func(context.Context, []byte) error { called = true; return nil })
	if !errors.Is(err, context.Canceled) || called {
		t.Fatal("read cancellation delivered code")
	}
	if err := p.generate(context.Background(), nil, func(context.Context, []byte) error { return nil }); !errors.Is(err, ErrInvalidGeneration) {
		t.Fatal("nil entropy accepted")
	}
	started := time.Now()
	err = p.Generate(context.Background(), func(ctx context.Context, _ []byte) error {
		deadline, ok := ctx.Deadline()
		if !ok || deadline.After(started.Add(5*time.Second+100*time.Millisecond)) {
			t.Fatal("unbounded callback")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenerationCancellationExhaustionAndUseFailure(t *testing.T) {
	p := mustProfile(t)
	calls := 0
	use := func(context.Context, []byte) error { calls++; return nil }
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.generate(cancelled, bytes.NewReader(make([]byte, 6)), use); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal("cancellation ignored")
	}
	if err := p.generate(nil, bytes.NewReader(nil), use); !errors.Is(err, ErrInvalidGeneration) {
		t.Fatal("nil context admitted")
	}
	if err := p.generate(context.Background(), bytes.NewReader(nil), nil); !errors.Is(err, ErrInvalidGeneration) {
		t.Fatal("nil callback admitted")
	}
	if err := (CodeProfile{}).generate(context.Background(), bytes.NewReader(nil), use); !errors.Is(err, ErrInvalidProfile) {
		t.Fatal("zero profile generation admitted")
	}
	for _, input := range [][]byte{nil, bytes.Repeat([]byte{255}, 10000)} {
		if err := p.generate(context.Background(), bytes.NewReader(input), use); !errors.Is(err, ErrGenerationUnavailable) || calls != 0 {
			t.Fatal("unbounded/failing entropy accepted")
		}
	}
	var borrowed []byte
	err := p.generate(context.Background(), bytes.NewReader(make([]byte, 6)), func(_ context.Context, code []byte) error {
		borrowed = code
		return errors.New("synthetic-sensitive-code")
	})
	if !errors.Is(err, ErrCodeUse) || strings.Contains(fmt.Sprint(err), "synthetic-sensitive-code") || !bytes.Equal(borrowed, make([]byte, 6)) {
		t.Fatal("callback failure disclosed or retained code")
	}
	// Cancellation raised by the callback overrides its failure, without retaining it.
	ctx, cancel := context.WithCancel(context.Background())
	err = p.generate(ctx, bytes.NewReader(make([]byte, 6)), func(context.Context, []byte) error { cancel(); return io.EOF })
	if !errors.Is(err, context.Canceled) {
		t.Fatal("terminal cancellation lost")
	}
}

func TestGenerationPanicStillClears(t *testing.T) {
	var borrowed []byte
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("callback panic swallowed")
			}
		}()
		_ = mustProfile(t).generate(context.Background(), bytes.NewReader(make([]byte, 6)), func(_ context.Context, b []byte) error { borrowed = b; panic("synthetic panic") })
	}()
	if !bytes.Equal(borrowed, make([]byte, 6)) {
		t.Fatal("panic retained code")
	}
}

func TestPublicGenerationConcurrent(t *testing.T) {
	p := mustProfile(t)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			err := p.Generate(context.Background(), func(ctx context.Context, b []byte) error {
				if ctx == nil || len(b) != 6 || !strings.ContainsAny(string(b), "0123456789") {
					t.Error("invalid generated code")
				}
				for _, v := range b {
					if v < '0' || v > '9' {
						t.Error("symbol outside profile")
					}
				}
				return nil
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

func FuzzCodeProfile(f *testing.F) {
	f.Add("0123456789", 6)
	f.Add("01", 20)
	f.Add("012345678\x00", 6)
	f.Fuzz(func(t *testing.T, alphabet string, length int) {
		s := profileSpec()
		s.Alphabet = alphabet
		s.Length = length
		p, err := NewCodeProfile(s)
		if err != nil {
			if p != (CodeProfile{}) {
				t.Fatal("invalid returned profile")
			}
			return
		}
		if got, e := p.Bindings(); e != nil || got != s {
			t.Fatal("profile projection changed")
		}
		err = p.Generate(context.Background(), func(_ context.Context, b []byte) error {
			if len(b) != length {
				t.Fatal("wrong generated length")
			}
			for _, v := range b {
				if !strings.ContainsRune(alphabet, rune(v)) {
					t.Fatal("foreign symbol")
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}
