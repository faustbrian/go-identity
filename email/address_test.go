package email_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	identifier "github.com/faustbrian/go-identifier"
	email "github.com/faustbrian/go-identity/email"
)

func addressPolicy(t *testing.T, fold bool) email.AddressPolicy {
	t.Helper()
	profile, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{
		ID: "email-v1", Version: 1, Unicode: identifier.UnicodeNormalizationNFC,
		CaseFold: fold, MaximumBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	return email.AddressPolicy{MaximumBytes: 4096, Canonicalization: profile, PreserveDisplay: true}
}

func TestAddressRejectsInvisibleSeparatorsAndLengthOverflow(t *testing.T) {
	p, err := email.NewAddressParser(addressPolicy(t, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"a\u0080b@example.invalid", "a\u00a0b@example.invalid", "a\u2007b@example.invalid", "a\u2028b@example.invalid", "a\u3000b@example.invalid", strings.Repeat("a", 65) + "@example.invalid", strings.Repeat("ü", 33) + "@example.invalid", "a@" + strings.Repeat("a", 64) + ".invalid", strings.Repeat("a", 4097)} {
		if _, err := p.Parse(email.AddressInput(input)); !errors.Is(err, email.ErrInvalidAddress) {
			t.Fatal("hostile boundary accepted")
		}
	}
	local := strings.Repeat("a", 64)
	domain := strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(local+"@"+domain) != 254 {
		t.Fatal("invalid boundary fixture")
	}
	if _, err := p.Parse(email.AddressInput(local + "@" + domain)); err != nil {
		t.Fatal("254-byte mailbox denied")
	}
	if _, err := p.Parse(email.AddressInput(local + "@" + domain + "e")); !errors.Is(err, email.ErrInvalidAddress) {
		t.Fatal("255-byte mailbox admitted")
	}
}

func TestAddressLocalPolicyCannotChangeIDNDestination(t *testing.T) {
	for _, fold := range []bool{false, true} {
		p, err := email.NewAddressParser(addressPolicy(t, fold))
		if err != nil {
			t.Fatal(err)
		}
		a, err := p.Parse("User@faß.de")
		want := "User@xn--fa-hia.de"
		if fold {
			want = "user@xn--fa-hia.de"
		}
		if err != nil || a.Canonical().Record().Value != want {
			t.Errorf("local fold=%t changed domain destination", fold)
		}
	}
}

func TestAddressRejectsMappedRootDots(t *testing.T) {
	p, err := email.NewAddressParser(addressPolicy(t, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, dot := range []string{".", "\u3002", "\uff0e", "\uff61"} {
		if _, err := p.Parse(email.AddressInput("a@example.invalid" + dot)); !errors.Is(err, email.ErrInvalidAddress) {
			t.Error("mapped root dot admitted")
		}
	}
}

func TestAddressLocalNormalizationIsSeparateFromDomainAdmission(t *testing.T) {
	profile, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{
		ID: "email-local-trim", Version: 1, Unicode: identifier.UnicodeNormalizationNFKC,
		CaseFold: true, TrimSpace: true, MaximumBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 4096, Canonicalization: profile})
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.Parse(" Ｕser @faß.de")
	if err != nil || a.Canonical().Record().Value != "user@xn--fa-hia.de" {
		t.Fatal("local policy changed domain or failed local normalization")
	}
	for _, input := range []string{"User＠example.invalid", "User@ example.invalid", "User@example.invalid "} {
		if _, err := p.Parse(email.AddressInput(input)); !errors.Is(err, email.ErrInvalidAddress) {
			t.Error("domain or separator repaired by local policy")
		}
	}
}

func TestAddressPolicyFreezesBoundsAndRetainsVersionedIdentity(t *testing.T) {
	policy := addressPolicy(t, false)
	policy.MaximumBytes = 32
	policy.PreserveDisplay = false
	p, err := email.NewAddressParser(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.MaximumBytes = 4096
	policy.PreserveDisplay = true
	a, err := p.Parse("User@example.invalid")
	if err != nil || a.Display() != "" || a.Canonical().Record().ProfileID != "email-v1" || a.Canonical().Record().ProfileVersion != 1 {
		t.Fatal("policy was mutable or lost binding")
	}
	if _, err := p.Parse(email.AddressInput(strings.Repeat("a", 33) + "@example.invalid")); !errors.Is(err, email.ErrInvalidAddress) {
		t.Fatal("borrowed config changed bounds")
	}
	otherProfile, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "email-v1", Version: 2, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	other, err := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 4096, Canonicalization: otherProfile})
	if err != nil {
		t.Fatal(err)
	}
	b, err := other.Parse("User@example.invalid")
	if err != nil || a.Canonical().Equal(b.Canonical()) {
		t.Fatal("profile version omitted from identity")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				b, err := p.Parse("User@EXAMPLE.invalid")
				if err != nil || !a.Canonical().Equal(b.Canonical()) {
					t.Error("concurrent immutable parsing differs")
				}
			}
		})
	}
	wg.Wait()
}

func TestAddressPolicyInvalidZeroAndDiagnostics(t *testing.T) {
	for _, policy := range []email.AddressPolicy{{}, {MaximumBytes: 4096}, {MaximumBytes: 2, Canonicalization: addressPolicy(t, false).Canonicalization}, {MaximumBytes: 4097, Canonicalization: addressPolicy(t, false).Canonicalization}} {
		if _, err := email.NewAddressParser(policy); !errors.Is(err, email.ErrInvalidPolicy) {
			t.Fatal("invalid policy accepted")
		}
	}
	var zero email.AddressParser
	if _, err := zero.Parse("a@example.invalid"); !errors.Is(err, email.ErrInvalidAddress) {
		t.Fatal("zero parser usable")
	}
	domainProfile, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "wrong-domain-policy", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, IDNA: true, MaximumBytes: 253})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 4096, Canonicalization: domainProfile}); !errors.Is(err, email.ErrInvalidPolicy) {
		t.Fatal("whole-mailbox IDNA allowed")
	}
	p, _ := email.NewAddressParser(addressPolicy(t, false))
	a, _ := p.Parse("sensitive@example.invalid")
	for _, value := range []any{a, email.AddressInput("sensitive@example.invalid")} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if strings.Contains(fmt.Sprintf(format, value), "sensitive") {
				t.Fatal("address logged")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, email.ErrSensitiveSerialization) {
			t.Fatal("implicit address export")
		}
	}
}

func TestAddressUnexportedConsumerCustodyDoesNotLeak(t *testing.T) {
	p, err := email.NewAddressParser(addressPolicy(t, false))
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.Parse("sensitive@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{struct{ address email.Address }{a}, struct {
		nested struct{ address email.Address }
	}{struct{ address email.Address }{a}}} {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(verb, value), "sensitive") {
				t.Fatal("nested address custody leaked")
			}
		}
	}
}

func FuzzAddressPolicyBoundedFixedPoints(f *testing.F) {
	profile, _ := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "email-fuzz", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 4096})
	p, _ := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 4096, Canonicalization: profile})
	for _, seed := range []string{"a@example.invalid", "User+tag@BÜCHER.example", "a..b@example.invalid", "a\x00@example.invalid", "δοκιμή@example.invalid", "User@faß.de", "a@example.invalid。", "a@example.invalid．", "a@example.invalid｡"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		a, err := p.Parse(email.AddressInput(input))
		if err != nil {
			if !errors.Is(err, email.ErrInvalidAddress) {
				t.Fatal("unclassified denial")
			}
			return
		}
		value := a.Canonical().Record().Value
		if len(value) > 254 || a.Display() != "" {
			t.Fatal("output boundary violated")
		}
		b, err := p.Parse(email.AddressInput(value))
		if err != nil || !a.Canonical().Equal(b.Canonical()) {
			t.Fatal("canonical roundtrip failed")
		}
	})
}

func TestAddressPreservesSelectedLocalCaseAndCanonicalizesDomain(t *testing.T) {
	p, err := email.NewAddressParser(addressPolicy(t, false))
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.Parse(email.AddressInput("User+tag@BÜCHER.example"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Canonical().Record().Value != "User+tag@xn--bcher-kva.example" || a.Display() != "User+tag@BÜCHER.example" {
		t.Fatal("address policy or display changed")
	}
	restored, err := p.Parse(email.AddressInput(a.Canonical().Record().Value))
	if err != nil || !restored.Canonical().Equal(a.Canonical()) {
		t.Fatal("canonical address is not a fixed point")
	}
	folded, err := email.NewAddressParser(addressPolicy(t, true))
	if err != nil {
		t.Fatal(err)
	}
	lower, err := folded.Parse(email.AddressInput("User+tag@BÜCHER.example"))
	if err != nil || lower.Canonical().Record().Value != "user+tag@xn--bcher-kva.example" {
		t.Fatal("explicit case policy ignored")
	}
}

func TestAddressRejectsMailboxAmbiguityWithoutDisclosingInput(t *testing.T) {
	p, err := email.NewAddressParser(addressPolicy(t, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"", "a@example.invalid,b@example.invalid", "Name <a@example.invalid>", "a(comment)@example.invalid", "a\r\n@example.invalid", "a@-example.invalid", "a@example.invalid.", "a@[127.0.0.1]", "\"a\"@example.invalid", "a..b@example.invalid", "a@exa_mple.invalid", "a@\xff.invalid"} {
		t.Run(input, func(t *testing.T) {
			a, err := p.Parse(email.AddressInput(input))
			if !errors.Is(err, email.ErrInvalidAddress) || a.Canonical().Record().Value != "" {
				t.Fatal("ambiguous address accepted")
			}
			if err.Error() != email.ErrInvalidAddress.Error() {
				t.Fatal("input disclosed")
			}
		})
	}
}
