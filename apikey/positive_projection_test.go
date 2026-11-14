package apikey_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func TestPositiveProjectionRejectsSourceFreeConstruction(t *testing.T) {
	if codec, err := apikey.NewPositiveProjectionCodec(apikey.PositiveProjectionConfig{}); err == nil || codec != nil {
		t.Fatal("source-free positive projection became an authentication owner")
	}
}

func TestPositiveProjectionAuthorityExpiryDuringEncryptionCannotReturnPrincipal(t *testing.T) {
	codec, source, request, _ := positiveProjectionFixture(t)
	admission, original, err := codec.Begin(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	// First Complete sample admits the original window. Its next sample after
	// actual encryption reaches the exclusive source deadline; no clock changes
	// are made to the operating system, primary or envelope implementation.
	source.expireOnClockRead = source.clockReads + 2
	out, publication, err := codec.Complete(context.Background(), admission, nil)
	if !errors.Is(err, apikey.ErrDenied) || out.Result != nil || out.Validate() != nil || out.State != original.State || out.Outcome != original.Outcome || out.AttemptID != original.AttemptID || out.Quota == nil || *out.Quota != *original.Quota || len(publication.Ciphertext) != 0 {
		t.Fatal("late crypto completion ignored original authority expiry or hid known debit", err)
	}
}

// This independent trusted source is a root contract fixture only. Real native
// current-owner/Work/quota/commit behavior is qualified by the public consumer.
type projectionContractSource struct {
	configuration                                apikey.Configuration
	now                                          time.Time
	verifications, observations, reconciliations int
	failure                                      error
	observedGrant                                []string
	last                                         apikey.AtomicVerificationResult
	clockReads                                   int
	expireOnClockRead                            int
	panicObservation                             bool
}

func (s *projectionContractSource) Now() time.Time {
	s.clockReads++
	if s.expireOnClockRead == s.clockReads {
		s.now = s.last.Result.ValidUntil
	}
	return s.now
}
func (*projectionContractSource) ApplyPermissionReduction(context.Context, apikey.PermissionReductionDecision) (apikey.PermissionReductionResult, error) {
	return apikey.PermissionReductionResult{}, apikey.ErrInvalid
}
func (*projectionContractSource) ReconcilePermissionReduction(context.Context, apikey.PermissionReductionReconcileQuery) (apikey.PermissionReductionResult, error) {
	return apikey.PermissionReductionResult{}, apikey.ErrInvalid
}
func (s *projectionContractSource) VerifyAndConsume(_ context.Context, r apikey.AtomicVerificationRequest) (apikey.AtomicVerificationResult, error) {
	s.verifications++
	if s.failure != nil {
		return apikey.AtomicVerificationResult{AttemptID: r.AttemptID, State: apikey.VerificationAttemptPossibleDebit, Outcome: identity.CommitOutcomeUnknown}, s.failure
	}
	c := s.configuration.Spec()
	owner, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: r.TenantID, Kind: apikey.OwnerUser, UserID: "user-a", Version: 2})
	record := apikey.Record{ID: "key-a", Owner: owner, Version: 3, AuthorityVersion: 2, RootID: "key-a", RootVersion: 2, ConfigurationID: c.ID, ConfigurationRevision: c.Revision, Status: apikey.KeyActive, Grant: []string{"invoice.read", "invoice.write"}, CreatedAt: s.now.Add(-time.Hour), ExpiresAt: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), Issuer: c.Issuer, Environment: c.Environment, Audience: c.Audience}
	result := apikey.VerificationResult{Record: record, Owner: owner, Grant: slices.Clone(record.Grant), PolicyVersion: 4, ConfigurationAuthority: apikey.ConfigurationAuthorityBinding{TenantID: r.TenantID, ConfigurationID: c.ID, Version: 7}, ReadStartedAt: s.now.Add(-time.Millisecond), VerifiedAt: s.now, ValidUntil: s.now.Add(18*time.Second - time.Millisecond)}
	out := apikey.AtomicVerificationResult{AttemptID: r.AttemptID, Fingerprint: sha256.Sum256([]byte(r.AttemptID)), Original: identity.RecoveryQuery{CommandID: identity.CommandID(r.AttemptID), TenantID: r.TenantID, UserID: "user-a", ActorID: "key-a", ActorKind: authorization.SubjectAPIKey, OperationID: "identity.apikey.verify"}, State: apikey.VerificationAttemptDebited, Outcome: identity.CommitOutcomeCommitted, Result: &result, Quota: &apikey.QuotaMetadata{TokenBucketPolicy: c.TokenBucket, Remaining: uint64(10 - s.verifications), ObservedAt: s.now}}
	if c.Quota == apikey.QuotaUnlimited {
		out.State, out.Quota = apikey.VerificationAttemptNotApplicable, nil
	}
	s.last = out
	return out, nil
}

func TestPositiveProjectionKnownUnlimitedHistoryRetainsOriginalScopeWithoutPrincipal(t *testing.T) {
	_, source, request, config := positiveProjectionFixture(t)
	spec := config.Configuration.Spec()
	spec.Quota, spec.TokenBucket = apikey.QuotaUnlimited, apikey.TokenBucketPolicy{}
	config.Configuration, _ = apikey.NewConfiguration(spec)
	source.configuration = config.Configuration
	request.DebitAmount = 0
	codec, err := apikey.NewPositiveProjectionCodec(config)
	if err != nil {
		t.Fatal(err)
	}
	admission, original, err := codec.Begin(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	source.now = original.Result.ValidUntil
	out, publication, err := codec.Complete(context.Background(), admission, nil)
	if !errors.Is(err, apikey.ErrDenied) || out.Result != nil || out.Validate() != nil || out.State != apikey.VerificationAttemptNotApplicable || out.Outcome != identity.CommitOutcomeCommitted || out.Original != original.Original || out.Fingerprint != original.Fingerprint || out.Quota != nil || len(publication.Ciphertext) != 0 {
		t.Fatal("later denial fabricated NotDebited or lost genuine unlimited commitment history", err)
	}
	for _, change := range []func(*apikey.AtomicVerificationResult){func(o *apikey.AtomicVerificationResult) { o.Fingerprint = [32]byte{} }, func(o *apikey.AtomicVerificationResult) { o.Outcome = identity.CommitOutcomeNotCommitted }, func(o *apikey.AtomicVerificationResult) { o.Original.CommandID = "" }, func(o *apikey.AtomicVerificationResult) { o.Original.ActorKind = authorization.SubjectServiceAccount }} {
		bad := out
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("incomplete/wrong-scope no-principal commitment accepted")
		}
	}
}
func (s *projectionContractSource) ReconcileVerifyAndConsume(_ context.Context, q apikey.VerificationReconcileQuery) (apikey.AtomicVerificationResult, error) {
	s.reconciliations++
	if q.AttemptID != s.last.AttemptID || q.Fingerprint != s.last.Fingerprint || q.Original != s.last.Original {
		return apikey.AtomicVerificationResult{}, apikey.ErrDenied
	}
	return s.last, nil
}
func (s *projectionContractSource) ObserveSourceAuthority(_ context.Context, b apikey.SourceAuthorityBinding) (apikey.SourceAuthorityObservation, error) {
	s.observations++
	if s.panicObservation {
		panic("controlled post-verifier authority failure")
	}
	grant := s.last.Result.Grant
	if s.observedGrant != nil {
		grant = s.observedGrant
	}
	return apikey.SourceAuthorityObservation{Binding: b, Record: s.last.Result.Record, Owner: s.last.Result.Owner, Grant: slices.Clone(grant), PolicyVersion: 4, ConfigurationAuthority: b.ConfigurationAuthority, GlobalVersion: 1, TenantVersion: 1, UserVersion: 3, UserAuthorityVersion: 2, AuthorizationVersion: 1, ReadStartedAt: s.last.Result.ReadStartedAt, VerifiedAt: s.now, ValidUntil: s.last.Result.ValidUntil}, nil
}

func TestPositiveProjectionPostVerifierPanicRetainsKnownReceiptWithoutPrincipal(t *testing.T) {
	codec, source, request, _ := positiveProjectionFixture(t)
	source.panicObservation = true
	var admission apikey.PositiveProjectionAdmission
	var out apikey.AtomicVerificationResult
	var err error
	func() {
		defer func() {
			if recover() != nil {
				t.Error("known committed source outcome escaped instead of returning fail-closed history")
			}
		}()
		admission, out, err = codec.Begin(context.Background(), request)
	}()
	original := source.last
	if err == nil || admission.Cacheable() || out.Result != nil || out.Validate() != nil || out.AttemptID != original.AttemptID || out.Fingerprint != original.Fingerprint || out.Original != original.Original || out.State != original.State || out.Outcome != original.Outcome || out.Quota == nil || *out.Quota != *original.Quota || source.verifications != 1 {
		t.Fatal("post-verifier authority panic lost known receipt/quota or retried native verification", err)
	}
}

func TestPositiveProjectionObtainedAuthorityCannotFallbackAfterRequiredPermissionWithdrawal(t *testing.T) {
	codec, source, request, _ := positiveProjectionFixture(t)
	source.observedGrant = []string{"invoice.write"}
	admission, original, err := codec.Begin(context.Background(), request)
	if err != nil {
		t.Fatal("setup known native debit then later authoritative narrowing", err)
	}
	out, publication, err := codec.Complete(context.Background(), admission, nil)
	if !errors.Is(err, apikey.ErrDenied) || out.Result != nil || out.Validate() != nil || out.AttemptID != original.AttemptID || out.Fingerprint != original.Fingerprint || out.Original != original.Original || out.Outcome != original.Outcome || out.State != original.State || out.Quota == nil || *out.Quota != *original.Quota || len(publication.Ciphertext) != 0 || source.verifications != 1 {
		t.Fatal("later obtained authority denied the required permission but codec returned the original principal or hid known debit", err)
	}
}

func TestPositiveProjectionObtainedAuthorityCannotFallbackAfterOriginalWindowExpires(t *testing.T) {
	codec, source, request, _ := positiveProjectionFixture(t)
	admission, original, err := codec.Begin(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	source.now = original.Result.ValidUntil
	out, publication, err := codec.Complete(context.Background(), admission, nil)
	if !errors.Is(err, apikey.ErrDenied) || out.Result != nil || out.Validate() != nil || out.AttemptID != original.AttemptID || out.Original != original.Original || out.State != original.State || out.Outcome != original.Outcome || out.Quota == nil || *out.Quota != *original.Quota || len(publication.Ciphertext) != 0 || source.verifications != 1 {
		t.Fatal("expired obtained authority became optional cache failure or renewed native principal", err)
	}
}

func positiveProjectionFixture(t *testing.T) (*apikey.PositiveProjectionCodec, *projectionContractSource, apikey.AtomicVerificationRequest, apikey.PositiveProjectionConfig) {
	t.Helper()
	spec := configuration(t).Spec()
	spec.Quota, spec.TokenBucket = apikey.QuotaTokenBucket, apikey.TokenBucketPolicy{Capacity: 10, RefillAmount: 1, RefillInterval: time.Hour}
	c, err := apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal(err)
	}
	source := &projectionContractSource{configuration: c, now: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)}
	var wrapping [32]byte
	if _, err := rand.Read(wrapping[:]); err != nil {
		t.Fatal(err)
	}
	keys, err := keyring.New(map[string][]byte{"projection-v1": wrapping[:]})
	clear(wrapping[:])
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	config := apikey.PositiveProjectionConfig{Configuration: c, TenantID: "tenant-a", Store: source, Verifier: source, Authority: source, Crypto: crypto, Clock: source, Namespace: "modern-user", DeploymentEpoch: 1, KeyReference: "projection-v1", MaximumDuration: time.Second, MaximumBytes: 65536}
	codec, err := apikey.NewPositiveProjectionCodec(config)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := apikey.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	request := apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(id), TenantID: config.TenantID, ConfigurationID: spec.ID, ConfigurationRevision: spec.Revision, Secret: secret, RequiredPermissions: []string{"invoice.read"}, DebitAmount: 1}
	return codec, source, request, config
}

func TestPositiveProjectionNewAttemptsKeepNativeQuotaAndOriginalCacheDeadline(t *testing.T) {
	codec, source, request, _ := positiveProjectionFixture(t)
	admission, first, err := codec.Begin(context.Background(), request)
	if err != nil || first.Validate() != nil || !admission.Cacheable() || source.verifications != 1 || source.observations != 1 {
		t.Fatal("first positive did not come from exactly one real source contract invocation", err)
	}
	firstOut, published, err := codec.Complete(context.Background(), admission, nil)
	if err != nil || firstOut.Validate() != nil || len(published.Ciphertext) == 0 || published.ReadStartedAt != first.Result.ReadStartedAt || published.ValidUntil != first.Result.ValidUntil {
		t.Fatal("genuine source could not publish original bounded encrypted metadata", err)
	}
	if _, _, err := codec.Complete(context.Background(), apikey.PositiveProjectionAdmission{}, published.Ciphertext); err == nil {
		t.Fatal("caller invented projection admission")
	}
	source.now = source.now.Add(5 * time.Second)
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	request.AttemptID = apikey.VerificationAttemptID(id)
	secondAdmission, second, err := codec.Begin(context.Background(), request)
	if err != nil || second.Validate() != nil || source.verifications != 2 || second.AttemptID == first.AttemptID || second.Quota.Remaining != 8 {
		t.Fatal("warm NEW attempt skipped source or reused historical quota", err)
	}
	narrowed, promoted, err := codec.Complete(context.Background(), secondAdmission, published.Ciphertext)
	if err != nil || narrowed.Validate() != nil || narrowed.AttemptID != second.AttemptID || narrowed.Fingerprint != second.Fingerprint || narrowed.Original != second.Original || narrowed.State != second.State || *narrowed.Quota != *second.Quota || narrowed.Result.ReadStartedAt != second.Result.ReadStartedAt || narrowed.Result.VerifiedAt != second.Result.VerifiedAt || narrowed.Result.ValidUntil != first.Result.ValidUntil || promoted.ReadStartedAt != published.ReadStartedAt || promoted.ValidUntil != published.ValidUntil || source.verifications != 2 {
		t.Fatal("warm projection promoted timestamps, original native attempt or quota", err)
	}
	query := apikey.VerificationReconcileQuery{AttemptID: second.AttemptID, TenantID: request.TenantID, Fingerprint: second.Fingerprint, Original: second.Original}
	if recovered, err := codec.Reconcile(context.Background(), query); err != nil || recovered.AttemptID != second.AttemptID || source.reconciliations != 1 || source.verifications != 2 {
		t.Fatal("projection recovery executed another verification/debit", err)
	}
}

func TestPositiveProjectionUnknownAndForeignAdmissionCannotPublishOrFallback(t *testing.T) {
	codec, source, request, config := positiveProjectionFixture(t)
	admission, _, err := codec.Begin(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := apikey.NewPositiveProjectionCodec(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, publication, err := foreign.Complete(context.Background(), admission, nil); err == nil || len(publication.Ciphertext) != 0 {
		t.Fatal("another codec accepted foreign live admission")
	}
	source.failure = apikey.ErrDebitOutcomeUnknown{AttemptID: request.AttemptID}
	unknown, out, err := codec.Begin(context.Background(), request)
	var debit apikey.ErrDebitOutcomeUnknown
	if !errors.As(err, &debit) || unknown.Cacheable() || out.Result != nil || out.Quota != nil || out.State != apikey.VerificationAttemptPossibleDebit || out.Outcome != identity.CommitOutcomeUnknown || source.verifications != 2 || source.observations != 1 {
		t.Fatal("cache hid or retried original possible debit", err)
	}
	for _, change := range []func(*apikey.PositiveProjectionConfig){func(c *apikey.PositiveProjectionConfig) { c.Verifier = nil }, func(c *apikey.PositiveProjectionConfig) { var typed *projectionContractSource; c.Store = typed }, func(c *apikey.PositiveProjectionConfig) { c.Authority = nil }, func(c *apikey.PositiveProjectionConfig) {
		s := c.Configuration.Spec()
		s.Algorithm, s.State, s.Quota, s.TokenBucket = apikey.AlgorithmLegacySHA256V1, apikey.ConfigurationVerifyOnly, apikey.QuotaUnlimited, apikey.TokenBucketPolicy{}
		c.Configuration, _ = apikey.NewConfiguration(s)
	}} {
		invalid := config
		change(&invalid)
		if codec, err := apikey.NewPositiveProjectionCodec(invalid); err == nil || codec != nil {
			t.Fatal("unsupported/source-free projection profile admitted")
		}
	}
}
