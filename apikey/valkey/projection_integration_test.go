//go:build integration

package apikeyvalkey_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeyvalkey "github.com/faustbrian/go-identity/apikey/valkey"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// An independent source contract owner, not an authentication engine or native
// substitute. The separate native consumer proves credential/current Work/quota.
type projectionSource struct {
	mu                                   sync.Mutex
	configuration                        apikey.Configuration
	now                                  time.Time
	createdAt, expiresAt                 time.Time
	calls, observations, reconciliations int
	remaining                            uint64
	clockReads, expireOnClockRead        int
	lastDeadline                         time.Time
	failure                              error
	revoked                              bool
	attempts                             map[apikey.VerificationAttemptID]apikey.AtomicVerificationResult
}

func (s *projectionSource) Now() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clockReads++
	if s.expireOnClockRead == s.clockReads {
		s.now = s.lastDeadline
	}
	return s.now
}
func (s *projectionSource) ApplyPermissionReduction(context.Context, apikey.PermissionReductionDecision) (apikey.PermissionReductionResult, error) {
	return apikey.PermissionReductionResult{}, apikey.ErrInvalid
}
func (s *projectionSource) ReconcilePermissionReduction(context.Context, apikey.PermissionReductionReconcileQuery) (apikey.PermissionReductionResult, error) {
	return apikey.PermissionReductionResult{}, apikey.ErrInvalid
}
func (s *projectionSource) VerifyAndConsume(_ context.Context, request apikey.AtomicVerificationRequest) (apikey.AtomicVerificationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if original, ok := s.attempts[request.AttemptID]; ok {
		return original, nil
	}
	query := identity.RecoveryQuery{CommandID: identity.CommandID(request.AttemptID), TenantID: request.TenantID, UserID: "user-a", ActorID: "key-a", ActorKind: authorization.SubjectAPIKey, OperationID: "identity.apikey.verify"}
	out := apikey.AtomicVerificationResult{AttemptID: request.AttemptID, Fingerprint: sha256.Sum256([]byte(request.AttemptID)), Original: query, Outcome: identity.CommitOutcomeCommitted, State: apikey.VerificationAttemptNotDebited}
	if s.failure != nil {
		out.State, out.Outcome = apikey.VerificationAttemptPossibleDebit, identity.CommitOutcomeUnknown
		return out, s.failure
	}
	if s.revoked {
		return out, apikey.ErrDenied
	}
	if s.remaining == 0 {
		return out, apikey.ErrDenied
	}
	s.remaining--
	owner, record := s.current()
	config := s.configuration.Spec()
	out.State = apikey.VerificationAttemptDebited
	out.Quota = &apikey.QuotaMetadata{TokenBucketPolicy: config.TokenBucket, Remaining: s.remaining, ObservedAt: s.now}
	out.Result = &apikey.VerificationResult{Record: record, Owner: owner, Grant: slices.Clone(record.Grant), PolicyVersion: 4, ConfigurationAuthority: apikey.ConfigurationAuthorityBinding{TenantID: request.TenantID, ConfigurationID: config.ID, Version: 7}, ReadStartedAt: s.now.Add(-time.Millisecond), VerifiedAt: s.now, ValidUntil: s.now.Add(18*time.Second - time.Millisecond)}
	s.lastDeadline = out.Result.ValidUntil
	s.attempts[request.AttemptID] = out
	return out, nil
}
func (s *projectionSource) current() (apikey.Owner, apikey.Record) {
	config := s.configuration.Spec()
	owner, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", Version: 2})
	return owner, apikey.Record{ID: "key-a", Owner: owner, Version: 3, AuthorityVersion: 2, RootID: "key-a", RootVersion: 2, ConfigurationID: config.ID, ConfigurationRevision: config.Revision, Status: apikey.KeyActive, Grant: []string{"invoice.read", "invoice.write"}, CreatedAt: s.createdAt, ExpiresAt: s.expiresAt, Issuer: config.Issuer, Environment: config.Environment, Audience: config.Audience}
}
func (s *projectionSource) ObserveSourceAuthority(_ context.Context, binding apikey.SourceAuthorityBinding) (apikey.SourceAuthorityObservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observations++
	if s.revoked {
		return apikey.SourceAuthorityObservation{}, apikey.ErrDenied
	}
	owner, record := s.current()
	return apikey.SourceAuthorityObservation{Binding: binding, Record: record, Owner: owner, Grant: slices.Clone(record.Grant), PolicyVersion: 4, ConfigurationAuthority: binding.ConfigurationAuthority, GlobalVersion: 1, TenantVersion: 1, UserVersion: 3, UserAuthorityVersion: 2, AuthorizationVersion: 1, ReadStartedAt: s.now.Add(-time.Millisecond), VerifiedAt: s.now, ValidUntil: s.now.Add(18*time.Second - time.Millisecond)}, nil
}
func (s *projectionSource) ReconcileVerifyAndConsume(_ context.Context, query apikey.VerificationReconcileQuery) (apikey.AtomicVerificationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconciliations++
	out, ok := s.attempts[query.AttemptID]
	if !ok || out.Fingerprint != query.Fingerprint || out.Original != query.Original {
		return apikey.AtomicVerificationResult{}, apikey.ErrDenied
	}
	return out, nil
}

func valkeyProjectionFixture(t *testing.T) (*apikeyvalkey.Cache, *projectionSource, apikey.AtomicVerificationRequest) {
	t.Helper()
	configuration, err := apikey.NewConfiguration(apikey.ConfigurationSpec{ID: "automation", Revision: 1, State: apikey.ConfigurationActive, Issuer: "https://issuer.example", Environment: "test", Audience: "resource-api", PermissionReduction: apikey.PermissionReductionNarrow, MaximumLifetime: 90 * 24 * time.Hour, MaximumRead: time.Second, ClockUncertainty: time.Second, DecisionRaceBudget: time.Second, Quota: apikey.QuotaTokenBucket, TokenBucket: apikey.TokenBucketPolicy{Capacity: 10, RefillAmount: 1, RefillInterval: time.Hour}, Cache: apikey.CacheDisabled})
	if err != nil {
		t.Fatal(err)
	}
	source := &projectionSource{configuration: configuration, now: time.Now().UTC().Truncate(time.Microsecond), remaining: 10, attempts: make(map[apikey.VerificationAttemptID]apikey.AtomicVerificationResult)}
	source.createdAt, source.expiresAt = source.now.Add(-time.Hour), source.now.Add(24*time.Hour)
	var wrapping, namespace [32]byte
	if _, err := rand.Read(wrapping[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(namespace[:]); err != nil {
		t.Fatal(err)
	}
	provider, err := keyring.New(map[string][]byte{"projection-v1": wrapping[:]})
	clear(wrapping[:])
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(provider)
	if err != nil {
		t.Fatal(err)
	}
	namespaceKey, err := apikeyvalkey.NewSecret(namespace[:])
	clear(namespace[:])
	if err != nil {
		t.Fatal(err)
	}
	trust, err := os.ReadFile(os.Getenv("APIKEY_VALKEY_CA_FILE"))
	if err != nil {
		t.Fatal("explicit owned Valkey TLS trust required")
	}
	password, err := os.ReadFile(os.Getenv("APIKEY_VALKEY_PASSWORD_FILE"))
	if err != nil {
		t.Fatal("explicit owned Valkey authentication required")
	}
	passwordSecret, err := apikeyvalkey.NewSecret(password)
	clear(password)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	cache, err := apikeyvalkey.New(ctx, apikeyvalkey.Config{Profile: "positive-projection", Topology: "standalone", Endpoint: os.Getenv("APIKEY_VALKEY_ENDPOINT"), Username: "default", Password: passwordSecret, NamespaceKey: namespaceKey, TrustPEM: trust, MaximumDuration: time.Second, CacheTimeout: 100 * time.Millisecond, MaximumConcurrent: 4, MaximumPayloadBytes: 65536}, apikey.PositiveProjectionConfig{Configuration: configuration, TenantID: "tenant-a", Store: source, Verifier: source, Authority: source, Crypto: crypto, Clock: source, Namespace: "contract-" + string(id), DeploymentEpoch: 1, KeyReference: "projection-v1", MaximumDuration: time.Second, MaximumBytes: 65536})
	if err != nil {
		t.Fatal("real TLS Valkey projection composition failed", err)
	}
	t.Cleanup(cache.Close)
	secret, err := apikey.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	return cache, source, apikey.AtomicVerificationRequest{TenantID: "tenant-a", ConfigurationID: configuration.Spec().ID, ConfigurationRevision: configuration.Spec().Revision, Secret: secret, RequiredPermissions: []string{"invoice.read"}, DebitAmount: 1}
}

func projectionAttempt(t *testing.T, request apikey.AtomicVerificationRequest) apikey.AtomicVerificationRequest {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	request.AttemptID = apikey.VerificationAttemptID(id)
	return request
}

func TestRealValkeyWarmNewAttemptKeepsNativeQuotaOriginalDeadlineAndLostInvalidationDenial(t *testing.T) {
	cache, source, request := valkeyProjectionFixture(t)
	first, err := cache.VerifyAndConsume(t.Context(), projectionAttempt(t, request))
	if err != nil || first.Validate() != nil || first.Result == nil || first.Quota == nil || first.Quota.Remaining != 9 {
		t.Fatal("first real Valkey projection lost actual source quota", err)
	}
	source.mu.Lock()
	source.now = source.now.Add(5 * time.Second)
	source.mu.Unlock()
	second, err := cache.VerifyAndConsume(t.Context(), projectionAttempt(t, request))
	if err != nil || second.Validate() != nil || second.Result == nil || second.Quota == nil || second.Quota.Remaining != 8 || second.AttemptID == first.AttemptID || second.Result.ValidUntil != first.Result.ValidUntil {
		t.Fatal("warm NEW attempt skipped native quota or renewed original cached deadline", err)
	}
	if source.calls != 2 || source.observations != 2 {
		t.Fatal("warm projection did not invoke current source exactly once per NEW attempt")
	}
	query := apikey.VerificationReconcileQuery{AttemptID: second.AttemptID, TenantID: request.TenantID, Fingerprint: second.Fingerprint, Original: second.Original}
	recovered, err := cache.ReconcileVerifyAndConsume(t.Context(), query)
	if err != nil || recovered.AttemptID != second.AttemptID || source.calls != 2 || source.reconciliations != 1 {
		t.Fatal("original reconciliation executed verification again", err)
	}
	// Deliberately deliver no cache invalidation. Native remains the authority.
	source.mu.Lock()
	source.revoked = true
	source.mu.Unlock()
	denied, err := cache.VerifyAndConsume(t.Context(), projectionAttempt(t, request))
	if !errors.Is(err, apikey.ErrDenied) || denied.Result != nil || source.calls != 3 {
		t.Fatal("warm projection resurrected revoked source after lost invalidation", err)
	}
}

func TestRealValkeyPossibleDebitPassesThroughWithoutFallbackOrProjection(t *testing.T) {
	cache, source, request := valkeyProjectionFixture(t)
	if _, err := cache.VerifyAndConsume(t.Context(), projectionAttempt(t, request)); err != nil {
		t.Fatal(err)
	}
	source.mu.Lock()
	source.failure = identity.UnknownCommitError{}
	source.mu.Unlock()
	out, err := cache.VerifyAndConsume(t.Context(), projectionAttempt(t, request))
	var unknown identity.UnknownCommitError
	if !errors.As(err, &unknown) || out.State != apikey.VerificationAttemptPossibleDebit || out.Outcome != identity.CommitOutcomeUnknown || out.Result != nil || source.calls != 2 || source.observations != 1 {
		t.Fatal("possible debit was hidden, retried or projected", err)
	}
}

func TestRealValkeyPublicationIOCannotReturnExpiredPrincipalOrHideKnownDebit(t *testing.T) {
	cache, source, request := valkeyProjectionFixture(t)
	source.mu.Lock()
	// Begin's clock, Complete's admission/final clocks, then the publication
	// pre-SET clock remain valid. The next sample after actual transport work
	// reaches the original exclusive deadline. No OS/DB/server clock is changed.
	source.expireOnClockRead = source.clockReads + 5
	source.mu.Unlock()
	out, err := cache.VerifyAndConsume(t.Context(), projectionAttempt(t, request))
	if !errors.Is(err, apikey.ErrDenied) || out.Result != nil || out.Validate() != nil || out.Outcome != identity.CommitOutcomeCommitted || out.State != apikey.VerificationAttemptDebited || out.Quota == nil || out.Quota.Remaining != 9 || source.calls != 1 {
		t.Fatal("post-publication expiry returned a principal, retried source or lost known debit", err)
	}
}
