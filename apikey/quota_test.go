package apikey_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

func TestTokenBucketConfigurationAndExactDebit(t *testing.T) {
	spec := configuration(t).Spec()
	original, _ := json.Marshal(spec)
	const retained = `{"ID":"automation","Revision":1,"State":1,"Issuer":"https://issuer.example","Environment":"test","Audience":"resource-api","PermissionReduction":1,"MaximumLifetime":7776000000000000,"MaximumRead":1000000000,"ClockUncertainty":1000000000,"DecisionRaceBudget":1000000000,"Quota":1,"Cache":1}`
	if string(original) != retained || strings.Contains(string(original), "TokenBucket") {
		t.Fatal("unlimited configuration identity changed")
	}
	spec.Quota = apikey.QuotaTokenBucket
	spec.TokenBucket = apikey.TokenBucketPolicy{Capacity: 1000, RefillAmount: 1000, RefillInterval: time.Hour}
	c, err := apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal("explicit native token bucket rejected", err)
	}
	secret, _ := apikey.GenerateSecret()
	id, _ := identity.NewCommandID()
	r := apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(id), TenantID: "tenant-a", ConfigurationID: c.Spec().ID, ConfigurationRevision: c.Spec().Revision, Secret: secret, RequiredPermissions: []string{"read"}, DebitAmount: 1}
	if err := r.Validate(c); err != nil {
		t.Fatal("positive bounded debit rejected", err)
	}
	for _, amount := range []uint64{0, 1001, ^uint64(0)} {
		r.DebitAmount = amount
		if r.Validate(c) == nil {
			t.Fatal("invalid debit admitted", amount)
		}
	}
	for _, change := range []func(*apikey.ConfigurationSpec){
		func(s *apikey.ConfigurationSpec) { s.TokenBucket.Capacity = 0 },
		func(s *apikey.ConfigurationSpec) { s.TokenBucket.Capacity = 1_000_001 },
		func(s *apikey.ConfigurationSpec) { s.TokenBucket.RefillAmount = 0 },
		func(s *apikey.ConfigurationSpec) { s.TokenBucket.RefillInterval = time.Nanosecond },
		func(s *apikey.ConfigurationSpec) { s.TokenBucket.RefillInterval = -time.Second },
		func(s *apikey.ConfigurationSpec) { s.Quota = apikey.QuotaUnlimited },
		func(s *apikey.ConfigurationSpec) {
			s.Algorithm = apikey.AlgorithmLegacySHA256V1
			s.State = apikey.ConfigurationVerifyOnly
		},
	} {
		bad := spec
		change(&bad)
		if _, err := apikey.NewConfiguration(bad); err == nil {
			t.Fatal("unsupported or inexact quota policy admitted")
		}
	}
}

func TestQuotaMetadataPrecisionAndArithmeticBounds(t *testing.T) {
	policy := apikey.TokenBucketPolicy{Capacity: 1_000_000, RefillAmount: ^uint64(0), RefillInterval: time.Duration(9223372036854775000)}
	if policy.Validate() != nil {
		t.Fatal("exact full-width refill/interval policy rejected")
	}
	at := time.Date(2026, 11, 13, 0, 0, 0, 123456000, time.UTC)
	good := apikey.QuotaMetadata{TokenBucketPolicy: policy, Remaining: policy.Capacity, ObservedAt: at}
	if good.Validate() != nil {
		t.Fatal("bounded exact metadata rejected")
	}
	for _, change := range []func(*apikey.QuotaMetadata){
		func(m *apikey.QuotaMetadata) { m.Remaining++ },
		func(m *apikey.QuotaMetadata) { m.ObservedAt = time.Time{} },
		func(m *apikey.QuotaMetadata) { m.ObservedAt = at.Add(time.Nanosecond) },
		func(m *apikey.QuotaMetadata) { m.ObservedAt = at.In(time.FixedZone("non-UTC", 3600)) },
		func(m *apikey.QuotaMetadata) { m.ObservedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
	} {
		bad := good
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("inexact/unsafe quota metadata admitted")
		}
	}
}

func TestFiniteQuotaResultPreservesOriginalHistoryWithoutPrincipal(t *testing.T) {
	r, _, at := organizationVerificationResult(t)
	r.State = apikey.VerificationAttemptDebited
	if r.Validate() == nil {
		t.Fatal("debit without quota observation admitted")
	}
	r.Quota = &apikey.QuotaMetadata{TokenBucketPolicy: apikey.TokenBucketPolicy{Capacity: 2, RefillAmount: 1, RefillInterval: time.Hour}, Remaining: 1, ObservedAt: at}
	if r.Validate() != nil {
		t.Fatal("known finite result rejected")
	}
	r.Result = nil
	if r.Validate() != nil {
		t.Fatal("historical known debit required a renewed principal")
	}
	r.State, r.Outcome = apikey.VerificationAttemptPossibleDebit, identity.CommitOutcomeUnknown
	if r.Validate() == nil {
		t.Fatal("possible debit exposed quota observation")
	}
	r.Quota = nil
	if r.Validate() != nil {
		t.Fatal("same original possible debit cannot be represented")
	}
}

func TestUndisclosedFiniteAttemptDoesNotClaimNonSubmission(t *testing.T) {
	id, _ := identity.NewCommandID()
	r := apikey.AtomicVerificationResult{AttemptID: apikey.VerificationAttemptID(id), State: apikey.VerificationAttemptPossibleDebit, Outcome: identity.CommitOutcomeUnknown}
	if r.Validate() != nil {
		t.Fatal("undisclosed original outcome cannot express possible debit")
	}
}
