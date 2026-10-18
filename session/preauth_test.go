package session

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func preAuthFixture(t *testing.T) (Token, DigestKey, PreAuthTransactionSpec) {
	t.Helper()
	token, err := ParseToken("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB")
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewDigestKey(7, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	remember, err := NewRememberPolicy(RememberPolicySpec{Choice: BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 10 * time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 7, 1, 2, 3, 4000, time.UTC)
	binding := PreAuthBinding{ID: identity.PreAuthTransactionID("AQEBAQEBAQEBAQEBAQEBAQ"), Intent: PreAuthIntent{TenantID: "tenant", Action: "identity.otp.signin", Origin: "https://identity.test", CallbackURL: "https://app.test/return?ok=1", Nonce: [32]byte{1}, Remember: remember, PolicyID: "login-policy", PolicyVersion: 3}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	cookie, err := token.PreAuthDigest(key, binding)
	if err != nil {
		t.Fatal(err)
	}
	return token, key, PreAuthTransactionSpec{Binding: binding, Cookie: cookie, Version: 1}
}

func TestPreAuthOriginalBindingAndExclusiveExpiry(t *testing.T) {
	_, _, spec := preAuthFixture(t)
	record, err := NewPreAuthTransaction(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Time{spec.Binding.IssuedAt, spec.Binding.ExpiresAt.Add(-time.Nanosecond)} {
		if err = record.Check(now, spec.Binding, spec.Cookie); err != nil {
			t.Fatal("original valid binding denied", err)
		}
	}
	for _, now := range []time.Time{{}, spec.Binding.IssuedAt.Add(-time.Nanosecond), spec.Binding.ExpiresAt, spec.Binding.ExpiresAt.Add(time.Nanosecond)} {
		if err = record.Check(now, spec.Binding, spec.Cookie); !errors.Is(err, ErrPreAuthDenied) {
			t.Fatal("invalid time admitted")
		}
	}
	projection, err := record.Bindings()
	if err != nil || projection.Version != 1 || !projection.Binding.ExpiresAt.Equal(spec.Binding.ExpiresAt) {
		t.Fatal("projection renewed original record")
	}
	before, _ := spec.Binding.Intent.Remember.Bindings()
	after, _ := projection.Binding.Intent.Remember.Bindings()
	if before != after {
		t.Fatal("remember policy changed")
	}
	projection.Binding.Intent.Nonce[0]++
	projection.Cookie.Sum[0]++
	if record.Check(spec.Binding.IssuedAt, spec.Binding, spec.Cookie) != nil {
		t.Fatal("projection mutated immutable record")
	}
	for _, value := range []any{record, spec, spec.Binding, spec.Binding.Intent} {
		if _, err = json.Marshal(value); err == nil {
			t.Fatal("private flow automatically serialized")
		}
		if got := fmt.Sprintf("%#v", value); got == "" || bytes.Contains([]byte(got), []byte("identity.test")) {
			t.Fatal("private flow disclosed")
		}
	}
}

func TestPreAuthUTCTimelineRoundTrip(t *testing.T) {
	token, key, fixture := preAuthFixture(t)
	for _, tc := range []struct {
		name   string
		issued time.Time
		valid  bool
	}{
		{"below UTC year one", time.Date(1, 1, 1, 0, 30, 0, 0, time.FixedZone("east", 3600)), false},
		{"above UTC year 9999", time.Date(9999, 12, 31, 23, 30, 0, 0, time.FixedZone("west", -3600)), false},
		{"inside lower boundary", time.Date(1, 1, 1, 2, 0, 0, 0, time.FixedZone("east", 3600)), true},
		{"inside upper boundary", time.Date(9999, 12, 31, 21, 0, 0, 0, time.FixedZone("west", -3600)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := fixture
			spec.Binding.IssuedAt = tc.issued
			spec.Binding.ExpiresAt = tc.issued.Add(5 * time.Minute)
			digest, digestErr := token.PreAuthDigest(key, spec.Binding)
			record, err := NewPreAuthTransaction(spec)
			if !tc.valid {
				if !errors.Is(err, ErrInvalidPreAuthTransaction) || !errors.Is(digestErr, ErrInvalidPreAuthTransaction) {
					t.Fatal("UTC-invalid timeline accepted")
				}
				return
			}
			if err != nil || digestErr != nil {
				t.Fatal("valid boundary denied", err, digestErr)
			}
			projection, err := record.Bindings()
			if err != nil || projection.Binding.IssuedAt.Location() != time.UTC || projection.Binding.ExpiresAt.Location() != time.UTC {
				t.Fatal("timeline not canonical UTC")
			}
			restored, err := NewPreAuthTransaction(projection)
			if err != nil || restored.Check(tc.issued, projection.Binding, projection.Cookie) != nil {
				t.Fatal("accepted timeline cannot round trip", err)
			}
			canonicalDigest, err := token.PreAuthDigest(key, projection.Binding)
			if err != nil || canonicalDigest != digest {
				t.Fatal("UTC normalization changed cookie digest", err)
			}
		})
	}
}

func TestPreAuthScopeSubstitutionAndDomainSeparation(t *testing.T) {
	token, key, spec := preAuthFixture(t)
	record, _ := NewPreAuthTransaction(spec)
	changes := []func(*PreAuthBinding){
		func(b *PreAuthBinding) { b.ID = "AgICAgICAgICAgICAgICAg" },
		func(b *PreAuthBinding) { b.Intent.TenantID = "foreign" },
		func(b *PreAuthBinding) { b.Intent.Action = "identity.password.signin" },
		func(b *PreAuthBinding) { b.Intent.Origin = "https://foreign.test" },
		func(b *PreAuthBinding) { b.Intent.CallbackURL = "https://foreign.test/return" },
		func(b *PreAuthBinding) { b.Intent.CallbackURL = "" },
		func(b *PreAuthBinding) { b.Intent.Nonce[0]++ },
		func(b *PreAuthBinding) { b.Intent.PolicyID = "other-policy" },
		func(b *PreAuthBinding) { b.Intent.PolicyVersion++ },
		func(b *PreAuthBinding) {
			p, _ := b.Intent.Remember.Bindings()
			p.IdleTTL -= time.Minute
			b.Intent.Remember, _ = NewRememberPolicy(p)
		},
		func(b *PreAuthBinding) { b.IssuedAt = b.IssuedAt.Add(time.Nanosecond) },
		func(b *PreAuthBinding) { b.ExpiresAt = b.ExpiresAt.Add(time.Nanosecond) },
	}
	for n, change := range changes {
		altered := spec.Binding
		change(&altered)
		if !errors.Is(record.Check(spec.Binding.IssuedAt, altered, spec.Cookie), ErrPreAuthDenied) {
			t.Fatalf("substitution %d admitted", n)
		}
		digest, err := token.PreAuthDigest(key, altered)
		if err != nil || digest == spec.Cookie {
			t.Fatalf("substitution %d not bound", n)
		}
	}
	sessionDigest, _ := token.Digest(key, string(spec.Binding.Intent.TenantID))
	if sessionDigest == spec.Cookie {
		t.Fatal("flow cookie reused session lookup domain")
	}
	rotated, _ := NewDigestKey(8, bytes.Repeat([]byte{9}, 32))
	digest, _ := token.PreAuthDigest(rotated, spec.Binding)
	if digest == spec.Cookie || record.Check(spec.Binding.IssuedAt, spec.Binding, digest) == nil {
		t.Fatal("unknown cookie key version admitted")
	}
	wrong, _ := ParseToken("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI")
	digest, _ = wrong.PreAuthDigest(key, spec.Binding)
	if record.Check(spec.Binding.IssuedAt, spec.Binding, digest) == nil {
		t.Fatal("foreign flow cookie admitted")
	}
}

func TestPreAuthCookieFramingIndependentVector(t *testing.T) {
	_, _, spec := preAuthFixture(t)
	// Independently framed using Ruby pack and OpenSSL::HMAC, not production
	// framing helpers. This pins field order, byte lengths, nonce, named key,
	// exact UTC timestamps and the original nanosecond remember durations.
	if hex.EncodeToString(spec.Cookie.Sum[:]) != "6600d7f35317d5efa981c5be8b670e5fda6fc74effb6fdfcb76f8ca00eb814df" {
		t.Fatal("cookie framing changed")
	}
	token, key, _ := preAuthFixture(t)
	local := spec.Binding
	local.IssuedAt = local.IssuedAt.In(time.FixedZone("test-local", 3600))
	local.ExpiresAt = local.ExpiresAt.In(time.FixedZone("test-local", 3600))
	got, err := token.PreAuthDigest(key, local)
	if err != nil || got != spec.Cookie {
		t.Fatal("equivalent UTC time changed cookie binding")
	}
	for _, cookie := range []TokenDigest{{}, {KeyVersion: 7}} {
		invalid := spec
		invalid.Cookie = cookie
		if _, err := NewPreAuthTransaction(invalid); err == nil {
			t.Fatal("missing cookie commitment reconstructed")
		}
	}
}

func TestPreAuthIdentifierBindingCannotBeSubstitutedOrErased(t *testing.T) {
	token, key, legacy := preAuthFixture(t)
	spec := legacy
	spec.Binding.Intent.IdentifierBinding = [32]byte{91}
	var err error
	spec.Cookie, err = token.PreAuthDigest(key, spec.Binding)
	if err != nil || spec.Cookie == legacy.Cookie {
		t.Fatal("identifier-bound flow reused unbound cookie domain")
	}
	// Independently framed with Ruby pack/OpenSSL::HMAC using the documented
	// bound domain, original scalar order and 32-byte identifier commitment.
	if hex.EncodeToString(spec.Cookie.Sum[:]) != "dcc1061eaeef6c8012e43cef2fee725d29551c6fd9cc37abd6850609292fa8bc" {
		t.Fatal("identifier-bound cookie framing changed")
	}
	record, err := NewPreAuthTransaction(spec)
	if err != nil || record.Check(spec.Binding.IssuedAt, spec.Binding, spec.Cookie) != nil {
		t.Fatal("original identifier-bound flow denied")
	}
	for _, identifier := range [][32]byte{{}, {92}} {
		changed := spec.Binding
		changed.Intent.IdentifierBinding = identifier
		digest, err := token.PreAuthDigest(key, changed)
		if err != nil || digest == spec.Cookie || !errors.Is(record.Check(spec.Binding.IssuedAt, changed, digest), ErrPreAuthDenied) {
			t.Fatal("changed or erased canonical identifier binding admitted")
		}
	}
	projection, err := record.Bindings()
	if err != nil || projection.Binding.Intent.IdentifierBinding != spec.Binding.Intent.IdentifierBinding {
		t.Fatal("identifier commitment lost in original custody")
	}
	projection.Binding.Intent.IdentifierBinding[0]++
	if record.Check(spec.Binding.IssuedAt, spec.Binding, spec.Cookie) != nil {
		t.Fatal("projected identifier commitment mutated retained original")
	}
}

func TestPreAuthRejectsMalformedBindings(t *testing.T) {
	token, key, spec := preAuthFixture(t)
	for _, change := range []func(*PreAuthBinding){
		func(b *PreAuthBinding) { b.ID = "" },
		func(b *PreAuthBinding) { b.Intent.TenantID = "" },
		func(b *PreAuthBinding) { b.Intent.Action = "" },
		func(b *PreAuthBinding) { b.Intent.Nonce = [32]byte{} },
		func(b *PreAuthBinding) { b.Intent.Remember = RememberPolicy{} },
		func(b *PreAuthBinding) { b.Intent.PolicyVersion = 0 },
		func(b *PreAuthBinding) { b.IssuedAt = time.Time{} },
		func(b *PreAuthBinding) { b.ExpiresAt = b.IssuedAt.Add(time.Minute - time.Nanosecond) },
		func(b *PreAuthBinding) { b.ExpiresAt = b.IssuedAt.Add(10*time.Minute + time.Nanosecond) },
	} {
		altered := spec
		change(&altered.Binding)
		if _, err := NewPreAuthTransaction(altered); err == nil {
			t.Fatal("invalid record reconstructed")
		}
		if _, err := token.PreAuthDigest(key, altered.Binding); err == nil {
			t.Fatal("invalid cookie binding accepted")
		}
	}
	for _, origin := range []string{"", "null", "https://identity.test/", "https://identity.test?q=1", "https://u:p@identity.test", "https://identity.test#x", "http://identity.test", "https://identity.test\n", "https:///missing", "https://identity.test:bad"} {
		altered := spec
		altered.Binding.Intent.Origin = origin
		if _, err := NewPreAuthTransaction(altered); err == nil {
			t.Fatal("invalid origin accepted")
		}
	}
	for _, callback := range []string{"/relative", "javascript:alert(1)", "https://u:p@app.test/", "https://app.test/#secret", "http://app.test/", "https://app.test/\r"} {
		altered := spec
		altered.Binding.Intent.CallbackURL = callback
		if _, err := NewPreAuthTransaction(altered); err == nil {
			t.Fatal("invalid callback accepted")
		}
	}
	for _, origin := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		altered := spec
		altered.Binding.Intent.Origin = origin
		if _, err := NewPreAuthTransaction(altered); err != nil {
			t.Fatal("explicit loopback development origin denied")
		}
	}
	spec.Version = 0
	if _, err := NewPreAuthTransaction(spec); err == nil {
		t.Fatal("zero version accepted")
	}
	if _, err := (PreAuthTransaction{}).Bindings(); err == nil {
		t.Fatal("zero record projected")
	}
	if !(errors.Is((PreAuthTransaction{}).Check(time.Now(), PreAuthBinding{}, TokenDigest{}), ErrPreAuthDenied)) {
		t.Fatal("zero record admitted")
	}
	if _, err := (Token{}).PreAuthDigest(key, spec.Binding); err == nil {
		t.Fatal("zero token accepted")
	}
	if _, err := token.PreAuthDigest(DigestKey{}, spec.Binding); err == nil {
		t.Fatal("zero key accepted")
	}
}

func FuzzPreAuthBindingURLs(f *testing.F) {
	for _, seed := range [][2]string{{"https://identity.test", "https://app.test/return"}, {"http://localhost:8080", ""}, {"null", "/relative"}, {"https://identity.test/", "javascript:alert(1)"}, {"https://identity.test#", "https://u:p@app.test"}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, origin, callback string) {
		_, _, spec := preAuthFixture(t)
		spec.Binding.Intent.Origin = origin
		spec.Binding.Intent.CallbackURL = callback
		record, err := NewPreAuthTransaction(spec)
		if len(origin) > 2048 || len(callback) > 2048 {
			if err == nil {
				t.Fatal("unbounded URL accepted")
			}
			return
		}
		if err != nil {
			if !errors.Is(err, ErrInvalidPreAuthTransaction) {
				t.Fatal("URL parser cause escaped")
			}
			return
		}
		got, err := record.Bindings()
		if err != nil || got.Binding.Intent.Origin != origin || got.Binding.Intent.CallbackURL != callback {
			t.Fatal("URL normalization changed exact intent")
		}
		if record.Check(spec.Binding.IssuedAt, spec.Binding, spec.Cookie) != nil {
			t.Fatal("accepted structural binding failed exact comparison")
		}
	})
}
