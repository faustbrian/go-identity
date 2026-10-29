package apikey_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

func legacyConfiguration(t *testing.T) apikey.Configuration {
	t.Helper()
	spec := configuration(t).Spec()
	spec.ID = "legacy-import"
	spec.Algorithm = apikey.AlgorithmLegacySHA256V1
	spec.State = apikey.ConfigurationVerifyOnly
	c, err := apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLegacyBareSecretVerifiesUnchangedWithoutModernParsingOrReveal(t *testing.T) {
	c := legacyConfiguration(t)
	const wire = "historical-bare-token-without-invented-prefix"
	if _, err := apikey.ParseSecret(wire); !errors.Is(err, apikey.ErrInvalid) {
		t.Fatal("modern parser admitted legacy wire")
	}
	secret, err := apikey.ParseLegacySecret(wire)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := secret.Digest(c)
	if err != nil {
		t.Fatal(err)
	}
	want, err := apikey.NewLegacyDigest(sha256.Sum256([]byte(wire)))
	if err != nil || !digest.Equal(want) {
		t.Fatal("legacy compatibility digest changed")
	}
	wrong, _ := apikey.ParseLegacySecret(wire + "-wrong")
	wrongDigest, _ := wrong.Digest(c)
	if digest.Equal(wrongDigest) {
		t.Fatal("wrong secret matched")
	}
	if _, err := secret.Digest(configuration(t)); !errors.Is(err, apikey.ErrInvalid) {
		t.Fatal("legacy text chose modern configuration")
	}
	modern, _ := apikey.GenerateSecret()
	pepper, _ := apikey.NewPepper(1, []byte(strings.Repeat("p", 32)))
	if _, err := modern.Digest(pepper, "tenant-a", c); !errors.Is(err, apikey.ErrInvalid) {
		t.Fatal("modern issuance digest admitted verify-only legacy configuration")
	}
	if c.AllowsIssuance() || !c.AllowsVerification() {
		t.Fatal("legacy configuration became an issuance policy")
	}
	for _, value := range []any{secret, digest, want} {
		if strings.Contains(fmt.Sprintf("%v %+v %#v", value, value, value), wire) {
			t.Fatal("legacy secret disclosed")
		}
		if _, err := json.Marshal(value); !errors.Is(err, apikey.ErrDisclosure) {
			t.Fatal("legacy custody serialized")
		}
	}
}

func TestLegacyConfigurationAndVerificationRequireExactServerSelectedArm(t *testing.T) {
	c := legacyConfiguration(t)
	if _, err := apikey.NewLegacyDigest([32]byte{}); !errors.Is(err, apikey.ErrInvalid) {
		t.Fatal("absent legacy verifier accepted")
	}
	disabledSpec := c.Spec()
	disabledSpec.State = apikey.ConfigurationDisabled
	disabled, err := apikey.NewConfiguration(disabledSpec)
	if err != nil || disabled.AllowsVerification() || disabled.AllowsIssuance() {
		t.Fatal("disabled legacy policy enabled authority")
	}
	for _, state := range []apikey.ConfigurationState{apikey.ConfigurationActive, apikey.ConfigurationDeprecated, apikey.ConfigurationUnspecified} {
		spec := c.Spec()
		spec.State = state
		if _, err := apikey.NewConfiguration(spec); !errors.Is(err, apikey.ErrInvalid) {
			t.Fatal("legacy configuration admitted unsupported state")
		}
	}
	id, _ := apikey.ParseVerificationAttemptID("AgICAgICAgICAgICAgICAg")
	legacy, _ := apikey.ParseLegacySecret("unchanged-historical-token")
	request := apikey.AtomicVerificationRequest{AttemptID: id, TenantID: "tenant-a", ConfigurationID: c.Spec().ID, ConfigurationRevision: c.Spec().Revision, LegacySecret: legacy}
	if err := request.Validate(c); err != nil {
		t.Fatal(err)
	}
	modern, _ := apikey.GenerateSecret()
	request.Secret = modern
	if err := request.Validate(c); !errors.Is(err, apikey.ErrInvalid) {
		t.Fatal("ambiguous modern and legacy credentials accepted")
	}
	request.LegacySecret = apikey.LegacySecret{}
	if err := request.Validate(c); !errors.Is(err, apikey.ErrInvalid) {
		t.Fatal("legacy policy accepted modern secret")
	}
	for _, value := range []string{"", strings.Repeat("a", 4097)} {
		if _, err := apikey.ParseLegacySecret(value); !errors.Is(err, apikey.ErrInvalid) {
			t.Fatal("unbounded historical secret accepted")
		}
	}
}

func TestModernConfigurationRetainsOriginalCanonicalBytesAndDigest(t *testing.T) {
	c := configuration(t)
	wire, err := json.Marshal(c.Spec())
	const original = `{"ID":"automation","Revision":1,"State":1,"Issuer":"https://issuer.example","Environment":"test","Audience":"resource-api","PermissionReduction":1,"MaximumLifetime":7776000000000000,"MaximumRead":1000000000,"ClockUncertainty":1000000000,"DecisionRaceBudget":1000000000,"Quota":1,"Cache":1}`
	if err != nil || string(wire) != original {
		t.Fatal("modern retained configuration bytes changed")
	}
	secret, _ := apikey.ParseSecret("idk_" + strings.Repeat("A", 43))
	pepper, _ := apikey.NewPepper(1, []byte(strings.Repeat("p", 32)))
	digest, err := secret.Digest(pepper, "tenant-a", c)
	if err != nil || hex.EncodeToString(digest.Sum[:]) != "9146462535600196dcd3ed1b66b656be71eda1fdf4fb3312e2ad8a84f4846e54" {
		t.Fatal("modern HMAC compatibility vector changed")
	}
}

func TestLegacyVerifyOnlyConfigurationCannotConstructAnIssuanceResult(t *testing.T) {
	c := legacyConfiguration(t)
	owner, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", Version: 1})
	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	record := apikey.Record{ID: "AQEBAQEBAQEBAQEBAQEBAQ", Owner: owner, Version: 1, AuthorityVersion: 1, ConfigurationID: c.Spec().ID, ConfigurationRevision: c.Spec().Revision, Status: apikey.KeyActive, CreatedAt: now, ExpiresAt: now.Add(time.Hour), RootID: "AQEBAQEBAQEBAQEBAQEBAQ", RootVersion: 1, Issuer: c.Spec().Issuer, Environment: c.Spec().Environment, Audience: c.Spec().Audience}
	secret, _ := apikey.GenerateSecret()
	if _, err := apikey.NewIssuanceResult(c, issuanceReceipt(identity.CommitOutcomeCommitted), &record, secret); !errors.Is(err, apikey.ErrInvalid) {
		t.Fatal("verify-only legacy configuration formed a reveal-once issuance result")
	}
}

func TestDigestOnlyImportRetainsCanonicalIdentityAndExplicitTombstone(t *testing.T) {
	c := legacyConfiguration(t)
	owner, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Version: 4})
	id, _ := apikey.ParseKeyID("01ARZ3NDEKTSV4RRFFQ69G5FAW")
	key, _ := identity.NewIdempotencyKey([]byte("digest-only-import"))
	digest, _ := apikey.NewLegacyDigest([32]byte{1})
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	record := apikey.Record{ID: id, Owner: owner, Version: 8, AuthorityVersion: 6, RootID: id, RootVersion: 6, PreviousID: "older-key", ConfigurationID: c.Spec().ID, ConfigurationRevision: c.Spec().Revision, Name: "existing integration", Status: apikey.KeyRevoked, Grant: []string{"invoice.read"}, CreatedAt: at, ExpiresAt: at.Add(24 * time.Hour), Issuer: c.Spec().Issuer, Environment: c.Spec().Environment, Audience: c.Spec().Audience}
	r := apikey.ImportRequest{Authentication: apikey.Authentication{TenantID: "tenant-a", Bearer: auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE")}, IdempotencyKey: key, Record: record, Digest: digest, SourceID: "source-system", SourceVersion: 12, Network: "192.0.2.1"}
	if err := r.Validate(c); err != nil || r.Record.ID != id || r.Record.Owner != owner || r.Record.Status != apikey.KeyRevoked || r.Record.PreviousID != "older-key" || r.SourceVersion != 12 {
		t.Fatal("import altered preserved source snapshot")
	}
	for i, change := range []func(*apikey.ImportRequest){
		func(r *apikey.ImportRequest) { r.SourceID = "" },
		func(r *apikey.ImportRequest) { r.SourceVersion = 0 },
		func(r *apikey.ImportRequest) { r.Digest = apikey.LegacyDigest{} },
		func(r *apikey.ImportRequest) { r.Record.CreatedAt = time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC) },
		func(r *apikey.ImportRequest) { r.Record.ExpiresAt = r.Record.ExpiresAt.Add(time.Nanosecond) },
		func(r *apikey.ImportRequest) { r.Record.Name = "\xff" },
		func(r *apikey.ImportRequest) {
			r.Record.Owner, _ = apikey.NewOwner(apikey.OwnerSpec{TenantID: "other", Kind: apikey.OwnerUser, UserID: "user", Version: 1})
		},
		func(r *apikey.ImportRequest) {
			r.Record.Owner = apikey.Owner{}
		},
	} {
		bad := r
		change(&bad)
		if err := bad.Validate(c); !errors.Is(err, apikey.ErrInvalid) {
			t.Fatalf("invalid source snapshot accepted at case %d", i)
		}
	}
	if _, err := json.Marshal(r); !errors.Is(err, apikey.ErrDisclosure) {
		t.Fatal("digest-only request serialized")
	}
}

func TestDigestOnlyImportRepresentsOrganizationSnapshotWithoutHumanSubstitution(t *testing.T) {
	c := legacyConfiguration(t)
	owner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerOrganization, OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Version: 4})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := apikey.ParseKeyID("01ARZ3NDEKTSV4RRFFQ69G5FAW")
	key, _ := identity.NewIdempotencyKey([]byte("organization-digest-only-import"))
	digest, _ := apikey.NewLegacyDigest([32]byte{1})
	at := time.Date(2016, 10, 1, 0, 0, 0, 123456000, time.UTC)
	r := apikey.ImportRequest{
		Authentication: apikey.Authentication{TenantID: "tenant-a", Bearer: auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE")},
		IdempotencyKey: key, Digest: digest, SourceID: "source-system", SourceVersion: 12, Network: "192.0.2.1",
		Record: apikey.Record{ID: id, Owner: owner, Version: 8, AuthorityVersion: 6, RootID: id, RootVersion: 6, PreviousID: "older-key",
			ConfigurationID: c.Spec().ID, ConfigurationRevision: c.Spec().Revision, Name: "existing organization integration", Status: apikey.KeyRevoked,
			Grant: []string{"invoice.read"}, CreatedAt: at, ExpiresAt: at.Add(20 * 365 * 24 * time.Hour), Issuer: c.Spec().Issuer, Environment: c.Spec().Environment, Audience: c.Spec().Audience},
	}
	if err := r.Validate(c); err != nil {
		t.Fatalf("organization source snapshot rejected: %v", err)
	}
	if r.Record.ID != id || r.Record.Owner != owner || r.Record.Owner.Spec().UserID != "" || r.Record.Version != 8 || r.Record.AuthorityVersion != 6 || r.Record.RootVersion != 6 || r.Record.PreviousID != "older-key" || r.Record.Status != apikey.KeyRevoked || !r.Record.CreatedAt.Equal(at) || !r.Record.ExpiresAt.Equal(at.Add(20*365*24*time.Hour)) || r.SourceID != "source-system" || r.SourceVersion != 12 {
		t.Fatal("organization import changed authenticated source metadata")
	}
	for _, test := range []struct {
		name   string
		change func(*apikey.ImportRequest)
	}{
		{"no-human-bearer", func(r *apikey.ImportRequest) { r.Authentication.Bearer = auth.NewBearerCredential("") }},
		{"cross-tenant", func(r *apikey.ImportRequest) { r.Authentication.TenantID = "tenant-b" }},
		{"source-unbound", func(r *apikey.ImportRequest) { r.SourceID = "" }},
		{"source-version-zero", func(r *apikey.ImportRequest) { r.SourceVersion = 0 }},
		{"no-digest", func(r *apikey.ImportRequest) { r.Digest = apikey.LegacyDigest{} }},
		{"no-idempotency", func(r *apikey.ImportRequest) { r.IdempotencyKey = identity.IdempotencyKey{} }},
		{"invalid-owner", func(r *apikey.ImportRequest) { r.Record.Owner = apikey.Owner{} }},
		{"unbound-root", func(r *apikey.ImportRequest) { r.Record.RootID = "other-key" }},
		{"unbound-root-epoch", func(r *apikey.ImportRequest) { r.Record.RootVersion++ }},
		{"zero-record-epoch", func(r *apikey.ImportRequest) { r.Record.Version = 0 }},
		{"zero-authority-epoch", func(r *apikey.ImportRequest) { r.Record.AuthorityVersion = 0 }},
		{"zero-creation-time", func(r *apikey.ImportRequest) { r.Record.CreatedAt = time.Time{} }},
		{"submicrosecond-expiry", func(r *apikey.ImportRequest) { r.Record.ExpiresAt = r.Record.ExpiresAt.Add(time.Nanosecond) }},
		{"no-expiry", func(r *apikey.ImportRequest) { r.Record.ExpiresAt = time.Time{} }},
		{"invalid-name", func(r *apikey.ImportRequest) { r.Record.Name = "\xff" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := r
			test.change(&bad)
			if !errors.Is(bad.Validate(c), apikey.ErrInvalid) {
				t.Fatal("invalid organization snapshot accepted")
			}
		})
	}
}

func TestLegacyImportPreservesHistoricalLifetimeBeyondModernIssuanceCeiling(t *testing.T) {
	c := legacyConfiguration(t)
	owner, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", Version: 1})
	created := time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)
	expires := time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
	r := apikey.Record{ID: "historical-key", Owner: owner, Version: 1, AuthorityVersion: 1, RootID: "historical-key", RootVersion: 1, ConfigurationID: c.Spec().ID, ConfigurationRevision: c.Spec().Revision, Name: "historical", Status: apikey.KeyActive, Grant: []string{"invoice.read"}, CreatedAt: created, ExpiresAt: expires, Issuer: c.Spec().Issuer, Environment: c.Spec().Environment, Audience: c.Spec().Audience}
	if err := r.Validate(c); err != nil || !r.CreatedAt.Equal(created) || !r.ExpiresAt.Equal(expires) {
		t.Fatal("legacy import applied a modern issuance lifetime or changed absolute times")
	}
	spec := c.Spec()
	spec.MaximumLifetime = 2 * 365 * 24 * time.Hour
	if _, err := apikey.NewConfiguration(spec); err != nil {
		t.Fatal("legacy metadata reused the modern issuance ceiling")
	}
	modern := configuration(t)
	r.ConfigurationID, r.ConfigurationRevision = modern.Spec().ID, modern.Spec().Revision
	if err := r.Validate(modern); !errors.Is(err, apikey.ErrInvalid) {
		t.Fatal("modern issuance lifetime ceiling weakened")
	}
	r.ConfigurationID, r.ConfigurationRevision = c.Spec().ID, c.Spec().Revision
	r.ExpiresAt = time.Time{}
	if err := r.Validate(c); !errors.Is(err, apikey.ErrInvalid) {
		t.Fatal("unsupported absent expiry was silently invented")
	}
}

func FuzzLegacySecretHashesOnlyBoundedUnchangedBytes(f *testing.F) {
	for _, wire := range []string{"historical", "idk_not-modern", "", "\x00\xffunchanged", strings.Repeat("x", 4096)} {
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, wire string) {
		secret, err := apikey.ParseLegacySecret(wire)
		if len(wire) == 0 || len(wire) > 4096 {
			if !errors.Is(err, apikey.ErrInvalid) {
				t.Fatal("unbounded legacy input accepted")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		digest, err := secret.Digest(legacyConfiguration(t))
		if err != nil || digest.Sum() != sha256.Sum256([]byte(wire)) {
			t.Fatal("historical bytes changed")
		}
	})
}

func TestLegacyCustodyStaysRedactedInsidePrivateDiagnosticWrappers(t *testing.T) {
	const raw = "private-wrapper-legacy-custody-sentinel"
	secret, err := apikey.ParseLegacySecret(raw)
	if err != nil {
		t.Fatal(err)
	}
	var sum [32]byte
	for i := range sum {
		sum[i] = 0xa5
	}
	digest, err := apikey.NewLegacyDigest(sum)
	if err != nil {
		t.Fatal(err)
	}
	// fmt does not invoke methods on an unexported enclosing field. Custody
	// must remain safe even when that reflection path bypasses Format itself.
	secretWrapper := struct{ credential apikey.LegacySecret }{secret}
	digestWrapper := struct{ metadata apikey.LegacyDigest }{digest}
	nestedSecret := struct{ packet any }{secretWrapper}
	nestedDigest := struct{ packet any }{digestWrapper}
	requestWrapper := struct {
		request apikey.AtomicVerificationRequest
	}{apikey.AtomicVerificationRequest{LegacySecret: secret}}
	t.Run("secret", func(t *testing.T) {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			for _, value := range []any{secretWrapper, &secretWrapper, nestedSecret, &nestedSecret, requestWrapper, &requestWrapper} {
				if strings.Contains(fmt.Sprintf(format, value), raw) {
					t.Fatal("private diagnostic wrapper disclosed legacy plaintext")
				}
			}
		}
	})
	t.Run("digest", func(t *testing.T) {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			for _, value := range []any{digestWrapper, &digestWrapper, nestedDigest, &nestedDigest} {
				text := fmt.Sprintf(format, value)
				if strings.Contains(text, "165 165") || strings.Contains(text, "0xa5, 0xa5") {
					t.Fatal("private diagnostic wrapper disclosed legacy verifier bytes")
				}
			}
		}
	})
}
