package phone_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/faustbrian/go-identity/phone"
)

func TestNumberCanonicalization(t *testing.T) {
	p, err := phone.NewNumberPolicy(phone.NumberPolicySpec{
		Profile:           phone.CurrentNumberProfile(),
		MaximumInputBytes: 64, AllowNational: true, DefaultRegion: "US", PreserveDisplay: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	n, err := p.Canonicalize(context.Background(), "2025550123")
	if err != nil {
		t.Fatal(err)
	}
	destination, err := n.DeliveryNumber()
	if err != nil || destination != "+12025550123" || n.Display() != "2025550123" {
		t.Fatal("wrong explicit projections")
	}
	international, err := p.Canonicalize(context.Background(), "+12025550123")
	if err != nil || !n.Equal(international) {
		t.Fatal("national and international identities differ")
	}
	record, err := n.Record()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := p.Restore(context.Background(), record)
	if err != nil || !restored.Equal(n) {
		t.Fatal("record did not round trip")
	}
	wire, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var fromWire phone.NumberRecord
	if err := json.Unmarshal(wire, &fromWire); err != nil {
		t.Fatal(err)
	}
	if restored, err := p.Restore(context.Background(), fromWire); err != nil || !restored.Equal(n) {
		t.Fatal("persistence wire round trip failed")
	}
}

func policy(t *testing.T, national, display bool) *phone.NumberPolicy {
	t.Helper()
	spec := phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64, AllowNational: national, PreserveDisplay: display}
	if national {
		spec.DefaultRegion = "US"
	}
	p, err := phone.NewNumberPolicy(spec)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNumberRejectsLenientParserInputs(t *testing.T) {
	p := policy(t, true, true)
	for _, raw := range []string{"", "202", "911", "112", "+12025550123x1", "+12025550123;ext=1", "tel:+12025550123", "+1-202-555-0123", "(202)5550123", "202 5550123", " +12025550123", "+12025550123\n", "1-800-FLOWERS", "12025550123", "011442079460123", "+4402079460123", "+9992025550123", "+012025550123", "++12025550123", "２０２５５５０１２３", "٢٠٢٥٥٥٠١٢٣", "\xff", "+12025550123\x00", strings.Repeat("1", 65)} {
		t.Run(fmt.Sprintf("input_%x", raw), func(t *testing.T) {
			n, err := p.Canonicalize(context.Background(), raw)
			if !errors.Is(err, phone.ErrNumberInvalid) {
				t.Fatal("invalid input admitted or wrong denial")
			}
			if _, err := n.DeliveryNumber(); err == nil {
				t.Fatal("denial returned number")
			}
		})
	}
}

func TestNumberPolicyFailsClosed(t *testing.T) {
	base := phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64}
	for _, change := range []func(*phone.NumberPolicySpec){
		func(s *phone.NumberPolicySpec) { s.Profile = phone.NumberProfile{} },
		func(s *phone.NumberPolicySpec) { s.Profile.ID += ".other" },
		func(s *phone.NumberPolicySpec) { s.Profile.Version++ },
		func(s *phone.NumberPolicySpec) { s.Profile.MetadataVersion = "v9.0.39" },
		func(s *phone.NumberPolicySpec) { s.MaximumInputBytes = 15 },
		func(s *phone.NumberPolicySpec) { s.MaximumInputBytes = 129 },
		func(s *phone.NumberPolicySpec) { s.DefaultRegion = "US" },
		func(s *phone.NumberPolicySpec) { s.AllowNational = true },
		func(s *phone.NumberPolicySpec) { s.AllowNational = true; s.DefaultRegion = "us" },
		func(s *phone.NumberPolicySpec) { s.AllowNational = true; s.DefaultRegion = "ZZ" },
		func(s *phone.NumberPolicySpec) { s.AllowNational = true; s.DefaultRegion = "001" },
	} {
		spec := base
		change(&spec)
		if _, err := phone.NewNumberPolicy(spec); !errors.Is(err, phone.ErrNumberPolicy) {
			t.Fatal("invalid policy admitted")
		}
	}
	for _, p := range []*phone.NumberPolicy{nil, {}} {
		if _, err := p.Canonicalize(context.Background(), "+12025550123"); !errors.Is(err, phone.ErrNumberPolicy) {
			t.Fatal("unset policy admitted")
		}
		if _, err := p.Restore(context.Background(), phone.NumberRecord{}); !errors.Is(err, phone.ErrNumberPolicy) {
			t.Fatal("unset restoration policy admitted")
		}
		if p.Profile() != (phone.NumberProfile{}) {
			t.Fatal("unset policy has profile")
		}
	}
	p := policy(t, false, false)
	if p.Profile() != phone.CurrentNumberProfile() {
		t.Fatal("wrong profile accessor")
	}
	if _, err := p.Canonicalize(context.Background(), "2025550123"); !errors.Is(err, phone.ErrNumberInvalid) {
		t.Fatal("implicit national region")
	}
	if _, err := p.Canonicalize(nil, "+12025550123"); !errors.Is(err, phone.ErrNumberInvalid) {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Canonicalize(ctx, "+12025550123"); !errors.Is(err, phone.ErrNumberCanceled) {
		t.Fatal("canceled context admitted")
	}
	spec := base
	frozen, err := phone.NewNumberPolicy(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.MaximumInputBytes = 0
	spec.Profile.ID = "changed"
	if _, err := frozen.Canonicalize(context.Background(), "+12025550123"); err != nil {
		t.Fatal("configuration did not freeze")
	}
}

func TestNumberInternationalIgnoresDefaultRegion(t *testing.T) {
	p := policy(t, true, true)
	n, err := p.Canonicalize(context.Background(), "+442079460123")
	if err != nil {
		t.Fatal(err)
	}
	r, err := n.Record()
	if err != nil || r.E164 != "+442079460123" || r.NationalRegion != "" {
		t.Fatal("international number inherited region")
	}
	gb, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64, AllowNational: true, DefaultRegion: "GB", PreserveDisplay: true})
	if err != nil {
		t.Fatal(err)
	}
	national, err := gb.Canonicalize(context.Background(), "02079460123")
	if err != nil || !national.Equal(n) {
		t.Fatal("GB national dial form failed")
	}
	if _, err := p.Restore(context.Background(), mustRecord(t, national)); !errors.Is(err, phone.ErrNumberInvalid) {
		t.Fatal("restoration reinterpreted original region")
	}
	if _, err := gb.Canonicalize(context.Background(), "2079460123"); !errors.Is(err, phone.ErrNumberInvalid) {
		t.Fatal("incomplete national dial form admitted")
	}
}

func mustRecord(t *testing.T, n phone.Number) phone.NumberRecord {
	t.Helper()
	r, err := n.Record()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestNumberRestorationValidatesEveryBinding(t *testing.T) {
	p := policy(t, true, true)
	n, err := p.Canonicalize(context.Background(), "2025550123")
	if err != nil {
		t.Fatal(err)
	}
	base := mustRecord(t, n)
	for _, change := range []func(*phone.NumberRecord){
		func(r *phone.NumberRecord) { r.E164 = "12025550123" },
		func(r *phone.NumberRecord) { r.E164 = "+12025550124" },
		func(r *phone.NumberRecord) { r.E164 = "+4402079460123" },
		func(r *phone.NumberRecord) { r.Profile.ID += ".other" },
		func(r *phone.NumberRecord) { r.Profile.Version++ },
		func(r *phone.NumberRecord) { r.Profile.MetadataVersion = "v9.0.39" },
		func(r *phone.NumberRecord) { r.Display = "" },
		func(r *phone.NumberRecord) { r.Display = strings.Repeat("1", 65) },
		func(r *phone.NumberRecord) { r.NationalRegion = "GB" },
		func(r *phone.NumberRecord) { r.NationalRegion = "" },
	} {
		r := base
		change(&r)
		if _, err := p.Restore(context.Background(), r); !errors.Is(err, phone.ErrNumberInvalid) {
			t.Fatal("ambiguous record admitted")
		}
	}
	if _, err := policy(t, true, false).Restore(context.Background(), base); !errors.Is(err, phone.ErrNumberInvalid) {
		t.Fatal("display retained without explicit policy")
	}
	without := policy(t, false, false)
	plain, err := without.Canonicalize(context.Background(), "+12025550123")
	if err != nil {
		t.Fatal(err)
	}
	if plain.Display() != "" || mustRecord(t, plain).NationalRegion != "" {
		t.Fatal("unexpected display retention")
	}
	if restored, err := without.Restore(context.Background(), mustRecord(t, plain)); err != nil || !restored.Equal(plain) {
		t.Fatal("no-display record did not round trip")
	}
	if _, err := p.Restore(nil, base); !errors.Is(err, phone.ErrNumberInvalid) {
		t.Fatal("nil restore context admitted")
	}
}

func TestNumberOpaqueDiagnosticsAndZero(t *testing.T) {
	p := policy(t, true, true)
	n, err := p.Canonicalize(context.Background(), "2025550123")
	if err != nil {
		t.Fatal(err)
	}
	var zero phone.Number
	if zero.Equal(zero) || zero.Equal(n) || n.Equal(zero) || zero.Display() != "" {
		t.Fatal("zero value admitted")
	}
	if _, err := zero.Record(); !errors.Is(err, phone.ErrNumberInvalid) {
		t.Fatal("zero persisted")
	}
	if _, err := zero.DeliveryNumber(); !errors.Is(err, phone.ErrNumberInvalid) {
		t.Fatal("zero delivered")
	}
	for _, value := range []any{n, &n, struct{ private phone.Number }{n}, mustRecord(t, n)} {
		for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q"} {
			formatted := fmt.Sprintf(verb, value)
			if strings.Contains(formatted, "2025550123") || strings.Contains(formatted, "12025550123") {
				t.Fatalf("diagnostic leak for %T with %s", value, verb)
			}
		}
	}
	for _, value := range []any{n, &n, zero} {
		if _, err := json.Marshal(value); !errors.Is(err, phone.ErrNumberDisclosure) {
			t.Fatal("implicit JSON disclosure")
		}
	}
	if _, err := n.MarshalText(); !errors.Is(err, phone.ErrNumberDisclosure) {
		t.Fatal("implicit text disclosure")
	}
	if n.LogValue().String() != "phone.Number(redacted)" || mustRecord(t, n).LogValue().String() != "phone.NumberRecord(redacted)" {
		t.Fatal("structured logging leak")
	}
	var logged strings.Builder
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("number", "number", n)
	if strings.Contains(logged.String(), "2025550123") {
		t.Fatal("slog leak")
	}
}

func TestNumberConcurrentUse(t *testing.T) {
	p := policy(t, true, true)
	n, err := p.Canonicalize(context.Background(), "2025550123")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 20 {
				v, err := p.Restore(context.Background(), mustRecord(t, n))
				if err != nil || !v.Equal(n) {
					t.Error("concurrent restoration diverged")
				}
			}
		})
	}
	wg.Wait()
}
