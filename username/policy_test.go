package username_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-identifier/v2"
	"github.com/faustbrian/go-identity/username"
)

func TestLatinCanonicalizationAndDisplay(t *testing.T) {
	p, err := username.NewPolicy(username.ReferencePolicySpec())
	if err != nil {
		t.Fatal(err)
	}
	n, err := p.Canonicalize(context.Background(), "Straße")
	if err != nil {
		t.Fatalf("legitimate Latin name rejected: %v", err)
	}
	if r := n.Record(); r.Canonical != "strasse" || r.Display != "Straße" || r.ProfileID != username.ProfileID || r.ProfileVersion != username.ProfileVersion {
		t.Fatal("canonical identity and original display must be distinct and profile bound")
	}
}

func reference(t testing.TB) *username.Policy {
	t.Helper()
	p, err := username.NewPolicy(username.ReferencePolicySpec())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDeterministicUnicodeAndSyntax(t *testing.T) {
	p := reference(t)
	for _, test := range []struct{ display, canonical string }{
		{"Cafe\u0301", "café"}, {"CAFÉ", "café"}, {"İpek", "i\u0307pek"},
		{"Kevin", "kevin"}, {"Ａｂｃ", "ａｂｃ"}, {"j\u030cane", "ǰane"},
		{"Abc_12.-", "abc_12.-"}, {"123", "123"}, {"\U0001df25ab", "\U0001df25ab"},
	} {
		n, err := p.Canonicalize(context.Background(), test.display)
		if err != nil || n.Record().Canonical != test.canonical || n.Display() != test.display {
			t.Fatalf("fixed Unicode case rejected or altered: %v", err)
		}
		again, err := p.Canonicalize(context.Background(), n.Record().Canonical)
		if err != nil || !n.Equal(again) {
			t.Fatal("canonicalization is not idempotent")
		}
	}
	for _, raw := range []string{" abc", "abc ", "a bc", "ab\nc", "ab\tc", "ab\x00c", "ab\u00a0c", "ab\u200dc", "ab\ufe0fc", "ab😀", "aαb", "aаb", "漢字名", "abc١", "\u0301abc", "ab1\u0301", "ab\u034fc", "ab\u0345", "ab\ua7cb", "ab\xff"} {
		if n, err := p.Canonicalize(context.Background(), raw); !errors.Is(err, username.ErrInvalid) || n != (username.Name{}) {
			t.Fatalf("prohibited syntax accepted: %v", err)
		}
	}
}

func TestBeforeAndAfterLengthAndFoldExpansion(t *testing.T) {
	p := reference(t)
	for _, test := range []struct {
		raw   string
		valid bool
	}{
		{"abc", true}, {"ab", false}, {strings.Repeat("a", 32), true}, {strings.Repeat("a", 33), false},
		{"e\u0301x", false}, {strings.Repeat("ß", 16), true}, {strings.Repeat("a", 31) + "ß", false},
		{"ßß", false}, {strings.Repeat("a", 31) + "e\u0301", false},
		{strings.Repeat("\U00010780", 32), true}, {strings.Repeat("\U00010780", 32) + "a", false},
	} {
		n, err := p.Canonicalize(context.Background(), test.raw)
		if (err == nil) != test.valid {
			t.Fatalf("length boundary (%d bytes, %d codepoints): %v", len(test.raw), utf8.RuneCountInString(test.raw), err)
		}
		if !test.valid && n != (username.Name{}) {
			t.Fatal("invalid name returned a partial value")
		}
		if test.valid && (len(n.Record().Canonical) > 128 || utf8.RuneCountInString(n.Record().Canonical) > 32) {
			t.Fatal("canonical bound exceeded")
		}
	}
}

func TestReservedEnrollmentDoesNotStrandLookupOrRestore(t *testing.T) {
	p := reference(t)
	for _, raw := range []string{"ADMIN", "Admin", "admin", "SuPpOrT", "ſupport"} {
		if n, err := p.Validate(context.Background(), raw); !errors.Is(err, username.ErrReserved) || n != (username.Name{}) {
			t.Fatal("folded exact reserved enrollment allowed")
		}
		n, err := p.Canonicalize(context.Background(), raw)
		if err != nil {
			t.Fatal("existing reserved lookup stranded")
		}
		if restored, err := p.Restore(context.Background(), n.Record()); err != nil || !restored.Equal(n) {
			t.Fatal("existing reserved persistence stranded")
		}
	}
	if _, err := p.Validate(context.Background(), "admin2"); err != nil {
		t.Fatal("reserved substring denied")
	}
	base, err := p.Validate(context.Background(), "Alice")
	if err != nil {
		t.Fatal(err)
	}
	spec := username.ReferencePolicySpec()
	spec.Reserved = username.ReservedNames{Version: 2, Names: []string{"alice"}}
	spec.Reserved.SHA256 = digest(spec.Reserved.Version, spec.Reserved.Names)
	later, err := username.NewPolicy(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = later.Validate(context.Background(), "Alice"); !errors.Is(err, username.ErrReserved) {
		t.Fatal("updated enrollment set ignored")
	}
	if _, err = later.Restore(context.Background(), base.Record()); err != nil {
		t.Fatal("updated enrollment set stranded existing record")
	}
}

func digest(version uint32, names []string) string {
	owned := append([]string(nil), names...)
	sort.Strings(owned)
	sum := sha256.Sum256([]byte(strconv.FormatUint(uint64(version), 10) + "\n" + strings.Join(owned, "\n") + "\n"))
	return hex.EncodeToString(sum[:])
}

func TestStartupManifestAndImmutableConfiguration(t *testing.T) {
	base := username.ReferencePolicySpec()
	if base.Reserved.SHA256 != digest(1, base.Reserved.Names) {
		t.Fatal("reference startup digest differs from specified wire format")
	}
	for _, mutate := range []func(*username.PolicySpec){
		func(s *username.PolicySpec) { s.Reserved.Version = 0 },
		func(s *username.PolicySpec) { s.Reserved.SHA256 = "" },
		func(s *username.PolicySpec) { s.Reserved.SHA256 = strings.Repeat("0", 64) },
		func(s *username.PolicySpec) { s.Reserved.Names = nil },
		func(s *username.PolicySpec) { s.Reserved.Names = []string{"admin", "admin"} },
		func(s *username.PolicySpec) { s.Reserved.Names[0] = "ADMIN" },
		func(s *username.PolicySpec) { s.Reserved.Names[0] = "aαb" },
		func(s *username.PolicySpec) { s.Reserved.Names[0] = strings.Repeat("a", 33) },
		func(s *username.PolicySpec) {
			s.Reserved.Names[0] = "replacement"
			s.Reserved.SHA256 = digest(1, s.Reserved.Names)
		},
		func(s *username.PolicySpec) { s.Reserved.Names = make([]string, 257) },
		func(s *username.PolicySpec) { s.ValidationTimeout = 0 },
		func(s *username.PolicySpec) { s.ValidationTimeout = -time.Second },
		func(s *username.PolicySpec) { s.ValidationTimeout = 31 * time.Second },
		func(s *username.PolicySpec) { s.Validators = []username.Validator{nil} },
		func(s *username.PolicySpec) { s.Validators = make([]username.Validator, 17) },
	} {
		s := username.ReferencePolicySpec()
		mutate(&s)
		if p, err := username.NewPolicy(s); !errors.Is(err, username.ErrPolicy) || p != nil {
			t.Fatal("invalid startup manifest accepted")
		}
	}
	spec := username.ReferencePolicySpec()
	called := 0
	spec.Validators = []username.Validator{func(context.Context, username.Name) error { called++; return nil }}
	p, err := username.NewPolicy(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Reserved.Names[0] = "alice"
	spec.Validators[0] = func(context.Context, username.Name) error { t.Fatal("caller-owned validator slice reused"); return nil }
	if _, err := p.Validate(context.Background(), "admin"); !errors.Is(err, username.ErrReserved) {
		t.Fatal("caller mutation changed reserved policy")
	}
	if _, err := p.Validate(context.Background(), "alice"); err != nil || called != 1 {
		t.Fatal("caller mutation changed policy")
	}
	if p.ReservedVersion() != 1 || p.ReservedChecksum() != base.Reserved.SHA256 {
		t.Fatal("validated manifest identity lost")
	}
	if _, err := p.Restore(context.Background(), username.Record{Canonical: "alice", Display: "Alice", ProfileID: username.ProfileID, ProfileVersion: username.ProfileVersion}); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatal("restoration reran enrollment callback")
	}
}

func TestValidatorsAreBoundedOrderedAndFailClosed(t *testing.T) {
	for _, mode := range []string{"accept", "error", "panic", "panic-nil", "cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := []int{}
			spec := username.ReferencePolicySpec()
			spec.ValidationTimeout = 20 * time.Millisecond
			spec.Validators = []username.Validator{
				func(c context.Context, n username.Name) error {
					calls = append(calls, 1)
					deadline, ok := c.Deadline()
					if !ok || time.Until(deadline) > spec.ValidationTimeout || n.Record().Canonical != "alice" {
						t.Fatal("callback did not receive bounded canonical name")
					}
					switch mode {
					case "error":
						return errors.New("private-user-callback-diagnostic")
					case "panic":
						panic("private-user-callback-panic")
					case "panic-nil":
						panic(nil)
					case "cancel":
						cancel()
					case "deadline":
						<-c.Done()
					}
					return nil
				},
				func(context.Context, username.Name) error { calls = append(calls, 2); return nil },
			}
			p, err := username.NewPolicy(spec)
			if err != nil {
				t.Fatal(err)
			}
			n, err := p.Validate(ctx, "Alice")
			want := username.ErrValidation
			if mode == "cancel" || mode == "deadline" {
				want = username.ErrCanceled
			}
			if mode == "accept" {
				if err != nil || len(calls) != 2 || calls[0] != 1 || calls[1] != 2 {
					t.Fatal("ordered callbacks failed")
				}
			} else if !errors.Is(err, want) || n != (username.Name{}) || len(calls) != 1 || strings.Contains(err.Error(), "private-user") {
				t.Fatal("validator denial leaked detail or continued")
			}
		})
	}
	spec := username.ReferencePolicySpec()
	spec.Validators = []username.Validator{func(context.Context, username.Name) error { t.Fatal("canceled callback ran"); return nil }}
	p, err := username.NewPolicy(spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = p.Validate(ctx, "Alice"); !errors.Is(err, username.ErrCanceled) {
		t.Fatal("pre-cancellation ignored")
	}
	if _, err = p.Canonicalize(nil, "Alice"); !errors.Is(err, username.ErrInvalid) {
		t.Fatal("nil context accepted")
	}
	if _, err = p.Canonicalize(ctx, "Alice"); !errors.Is(err, username.ErrCanceled) {
		t.Fatal("lookup cancellation ignored")
	}
}

func TestRestoreRejectsForgedCanonicalProfileOrDisplay(t *testing.T) {
	p := reference(t)
	n, err := p.Canonicalize(context.Background(), "Cafe\u0301")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p.Restore(context.Background(), n.Record()); err != nil || got.Display() != n.Display() || !got.Equal(n) {
		t.Fatal("valid roundtrip failed")
	}
	for _, mutate := range []func(*username.Record){
		func(r *username.Record) { r.Canonical = "CAFÉ" },
		func(r *username.Record) { r.Canonical = "cafe\u0301" },
		func(r *username.Record) { r.Canonical = "other" },
		func(r *username.Record) { r.ProfileID = "other.profile" },
		func(r *username.Record) { r.ProfileVersion++ },
		func(r *username.Record) { r.Display = "other" },
		func(r *username.Record) { r.Display = " cafe" },
		func(r *username.Record) { r.Display = "" },
	} {
		r := n.Record()
		mutate(&r)
		if got, err := p.Restore(context.Background(), r); !errors.Is(err, username.ErrInvalid) || got != (username.Name{}) {
			t.Fatal("forged persistence accepted")
		}
	}
	var zero username.Policy
	var nilPolicy *username.Policy
	for _, p := range []*username.Policy{nilPolicy, &zero} {
		if _, err := p.Canonicalize(context.Background(), "alice"); !errors.Is(err, username.ErrPolicy) {
			t.Fatal("uninitialized policy accepted")
		}
	}
	if nilPolicy.ReservedVersion() != 0 || nilPolicy.ReservedChecksum() != "" {
		t.Fatal("nil metadata is not empty")
	}
	if _, err := nilPolicy.Restore(context.Background(), n.Record()); !errors.Is(err, username.ErrPolicy) {
		t.Fatal("nil restore accepted")
	}
}

func TestSensitiveNamesAndRecordsAreRedacted(t *testing.T) {
	p := reference(t)
	n, err := p.Canonicalize(context.Background(), "PrivateUsername")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{n, n.Record()} {
		for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q"} {
			if output := fmt.Sprintf(verb, v); strings.Contains(strings.ToLower(output), "privateusername") {
				t.Fatal("formatter disclosed PII")
			}
		}
		var output bytes.Buffer
		slog.New(slog.NewJSONHandler(&output, nil)).Info("test", "name", v)
		if strings.Contains(strings.ToLower(output.String()), "privateusername") {
			t.Fatal("structured logging disclosed PII")
		}
	}
	if _, err := json.Marshal(n); !errors.Is(err, username.ErrDisclosure) {
		t.Fatal("implicit JSON disclosure allowed")
	}
	if _, err := n.MarshalText(); !errors.Is(err, username.ErrDisclosure) {
		t.Fatal("implicit text disclosure allowed")
	}
	data, err := json.Marshal(n.Record())
	if err != nil || !bytes.Contains(data, []byte("privateusername")) || !bytes.Contains(data, []byte("PrivateUsername")) {
		t.Fatal("explicit sensitive record lost canonical or display")
	}
	if n.Record().ProfileID != username.ProfileID {
		t.Fatal("explicit canonical projection lacks profile")
	}
}

func TestPrivateEnclosingDiagnosticsDoNotExposeOpaqueName(t *testing.T) {
	n, err := reference(t).Canonicalize(context.Background(), "PrivateUsername")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{struct{ private username.Name }{n}, &struct{ private username.Name }{n}} {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			if output := fmt.Sprintf(verb, v); strings.Contains(strings.ToLower(output), "privateusername") {
				t.Fatal("private enclosing field bypassed redaction and disclosed PII")
			}
		}
	}
}

func TestConcurrentImmutablePolicyReuse(t *testing.T) {
	p := reference(t)
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			for range 20 {
				n, err := p.Validate(context.Background(), "Straße")
				if err != nil || n.Record().Canonical != "strasse" {
					t.Error("concurrent canonicalization changed policy")
				}
			}
		})
	}
	group.Wait()
}

func TestProfileInteroperabilityAndZeroNameProjection(t *testing.T) {
	p := reference(t)
	n, err := p.Canonicalize(context.Background(), "Straße")
	if err != nil {
		t.Fatal(err)
	}
	primitive, err := identifier.Normalize(identifier.Input("Straße"), p.Profile())
	if err != nil || primitive.Record().Value != n.Record().Canonical || primitive.Record().ProfileID != n.Record().ProfileID || primitive.Record().ProfileVersion != n.Record().ProfileVersion {
		t.Fatal("public identifier profile disagrees with policy")
	}
	var none username.Name
	if none.Record() != (username.Record{}) || none.Display() != "" || none.Equal(n) {
		t.Fatal("zero name became a persistence identity")
	}
	var noPolicy *username.Policy
	if _, err := identifier.Normalize(identifier.Input("Alice"), noPolicy.Profile()); err == nil {
		t.Fatal("nil policy returned a valid public profile")
	}
}

func TestValidatorPreservesEarlierCallerDeadlineAndDeniesAfterIt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	want, _ := ctx.Deadline()
	spec := username.ReferencePolicySpec()
	spec.Validators = []username.Validator{func(bounded context.Context, _ username.Name) error {
		got, exists := bounded.Deadline()
		if !exists || !got.Equal(want) {
			t.Fatal("earlier caller deadline extended")
		}
		<-bounded.Done()
		return errors.New("private callback error after deadline")
	}}
	p, err := username.NewPolicy(spec)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := p.Validate(ctx, "Alice"); !errors.Is(err, username.ErrCanceled) || n != (username.Name{}) {
		t.Fatal("expired caller deadline did not deny")
	}
}

func FuzzCanonicalization(f *testing.F) {
	for _, seed := range []string{"Alice", "Straße", "Cafe\u0301", "İpek", "aаb", "ab\u034f", strings.Repeat("ß", 17), "\xff", "\U0001df25ab"} {
		f.Add(seed)
	}
	p := reference(f)
	f.Fuzz(func(t *testing.T, input string) {
		n, err := p.Canonicalize(context.Background(), input)
		if err != nil {
			if n != (username.Name{}) {
				t.Fatal("denied input returned partial identity")
			}
			return
		}
		r := n.Record()
		if r.Display != input || r.ProfileID != username.ProfileID || r.ProfileVersion != username.ProfileVersion || !utf8.ValidString(r.Canonical) || len(input) > 128 || len(r.Canonical) > 128 || utf8.RuneCountInString(input) < 3 || utf8.RuneCountInString(input) > 32 || utf8.RuneCountInString(r.Canonical) < 3 || utf8.RuneCountInString(r.Canonical) > 32 {
			t.Fatal("successful canonicalization violated bounds or identity")
		}
		again, err := p.Canonicalize(context.Background(), r.Canonical)
		if err != nil || !again.Equal(n) {
			t.Fatal("canonical value is not a fixed point")
		}
		loaded, err := p.Restore(context.Background(), r)
		if err != nil || !loaded.Equal(n) || loaded.Display() != input {
			t.Fatal("successful record cannot restore")
		}
	})
}

func TestNameEqualityIsCanonicalDisplayIndependentAndProfileBound(t *testing.T) {
	p := reference(t)
	first, err := p.Canonicalize(context.Background(), "Cafe\u0301")
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.Canonicalize(context.Background(), "CAFÉ")
	if err != nil {
		t.Fatal(err)
	}
	if first.Display() == second.Display() || !first.Equal(second) || !second.Equal(first) || !first.Equal(first) {
		t.Fatal("equivalent canonical names did not compare equal independent of display")
	}
	other, err := p.Canonicalize(context.Background(), "other")
	if err != nil {
		t.Fatal(err)
	}
	var zero username.Name
	if first.Equal(other) || other.Equal(first) || first.Equal(zero) || zero.Equal(first) || zero.Equal(zero) {
		t.Fatal("different or invalid canonical names compared equal")
	}
	restored, err := p.Restore(context.Background(), first.Record())
	if err != nil || !first.Equal(restored) {
		t.Fatal("persisted exact-profile name lost equality")
	}
	for _, change := range []func(*username.Record){
		func(r *username.Record) { r.ProfileID = "identity.username.other-v1" },
		func(r *username.Record) { r.ProfileVersion++ },
	} {
		record := first.Record()
		change(&record)
		forged, err := p.Restore(context.Background(), record)
		if !errors.Is(err, username.ErrInvalid) || first.Equal(forged) || forged.Equal(first) {
			t.Fatal("a different profile entered valid-name equality")
		}
	}
}
