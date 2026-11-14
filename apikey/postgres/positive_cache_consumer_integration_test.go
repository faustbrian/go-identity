//go:build integration

package postgres_test

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	apikeyvalkey "github.com/faustbrian/go-identity/apikey/valkey"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// Count calls without replacing authentication, persistence or quota behavior.
// The genuine native owner receives every request and reconciliation unchanged.
type countedCachePrimary struct {
	source *apikeypg.Service
	calls  atomic.Uint64
}

func (p *countedCachePrimary) VerifyAndConsume(ctx context.Context, r apikey.AtomicVerificationRequest) (apikey.AtomicVerificationResult, error) {
	p.calls.Add(1)
	return p.source.VerifyAndConsume(ctx, r)
}

func (p *countedCachePrimary) ReconcileVerifyAndConsume(ctx context.Context, q apikey.VerificationReconcileQuery) (apikey.AtomicVerificationResult, error) {
	return p.source.ReconcileVerifyAndConsume(ctx, q)
}

func nativePositiveCache(t *testing.T, f nativeConsumerFixture, c apikeypg.ServiceConfig, source *apikeypg.Service) (*apikeyvalkey.Cache, *countedCachePrimary) {
	t.Helper()
	trust, err := os.ReadFile(os.Getenv("APIKEY_VALKEY_CA_FILE"))
	if err != nil {
		t.Fatal("explicit task-owned Valkey TLS trust required")
	}
	password, err := os.ReadFile(os.Getenv("APIKEY_VALKEY_PASSWORD_FILE"))
	if err != nil {
		t.Fatal("explicit task-owned Valkey authentication required")
	}
	passwordSecret, err := apikeyvalkey.NewSecret(password)
	clear(password)
	if err != nil {
		t.Fatal("Valkey authentication configuration rejected")
	}
	var namespace [32]byte
	if _, err := rand.Read(namespace[:]); err != nil {
		t.Fatal("cache namespace entropy unavailable")
	}
	namespaceKey, err := apikeyvalkey.NewSecret(namespace[:])
	clear(namespace[:])
	if err != nil {
		t.Fatal("cache namespace configuration rejected")
	}
	keys, err := keyring.New(c.RetainedEnvelopeKeys)
	if err != nil {
		t.Fatal("native envelope key configuration rejected")
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	store, err := apikeypg.NewPermissionReductionStore(source, apikeypg.PermissionReductionStoreConfig{
		TenantID: baselineTenant, UserID: f.user,
		ActorID: reductionActor, ActorPolicyNamespace: reductionNamespace,
	})
	if err != nil {
		t.Fatal("real permission-maintenance owner composition failed", err)
	}
	primary := &countedCachePrimary{source: source}
	cache, err := apikeyvalkey.New(f.ctx, apikeyvalkey.Config{
		Profile: "positive-projection", Topology: "standalone",
		Endpoint: os.Getenv("APIKEY_VALKEY_ENDPOINT"), Username: "default",
		Password: passwordSecret, NamespaceKey: namespaceKey, TrustPEM: trust,
		MaximumDuration: 4 * time.Second, CacheTimeout: 250 * time.Millisecond,
		MaximumConcurrent: 4, MaximumPayloadBytes: 65536,
	}, apikey.PositiveProjectionConfig{
		Configuration: c.Configuration, TenantID: baselineTenant,
		Store: store, Verifier: primary, Authority: source,
		Crypto: crypto, Clock: c.Clock, Namespace: "native-" + string(commandID(t)),
		DeploymentEpoch: 1, KeyReference: c.ActiveEnvelopeKeyID,
		MaximumDuration: 4 * time.Second, MaximumBytes: 65536,
	})
	if err != nil {
		t.Fatal("real native and TLS Valkey composition failed", err)
	}
	t.Cleanup(cache.Close)
	return cache, primary
}

func TestNativePositiveCacheQuotaRetryAndNarrowing(t *testing.T) {
	f := setupNativeConsumer(t)
	installQuota(t, f)
	c := quotaConfiguration(t, f.config, apikey.TokenBucketPolicy{Capacity: 5, RefillAmount: 1, RefillInterval: time.Hour})
	source, _, request := quotaKey(t, f, c)
	cache, primary := nativePositiveCache(t, f, c, source)
	original, err := cache.VerifyAndConsume(f.ctx, request)
	if err != nil || original.Validate() != nil || original.Result == nil || original.Quota == nil || original.Quota.Remaining != 4 || primary.calls.Load() != 1 {
		t.Fatal("cold projection did not preserve one genuine native debit", err)
	}
	originalRequest := request
	request.AttemptID = apikey.VerificationAttemptID(commandID(t))
	warm, err := cache.VerifyAndConsume(f.ctx, request)
	if err != nil || warm.Result == nil || warm.Quota == nil || warm.Quota.Remaining != 3 || primary.calls.Load() != 2 || warm.Result.ValidUntil.After(original.Result.ValidUntil) || warm.AttemptID == original.AttemptID || warm.Fingerprint == original.Fingerprint {
		t.Fatal("warm new attempt reused quota/history or renewed the cached deadline", err)
	}
	replayed, err := cache.VerifyAndConsume(f.ctx, originalRequest)
	if err != nil || replayed.Result == nil || replayed.Quota == nil || *replayed.Quota != *original.Quota || replayed.Fingerprint != original.Fingerprint || replayed.Result.ValidUntil.After(original.Result.ValidUntil) || primary.calls.Load() != 3 {
		t.Fatal("matching retry spent another token or replaced original custody", err)
	}
	// No invalidation is sent to Valkey: only current native policy/epochs change.
	f.deniedGrant.Store(true)
	advanceUserPolicy(t, f.ctx, f.pool, c.Profile.PolicyNamespace, f.user)
	request.AttemptID = apikey.VerificationAttemptID(commandID(t))
	narrowed, err := cache.VerifyAndConsume(f.ctx, request)
	if err != nil || narrowed.Result == nil || narrowed.Quota == nil || narrowed.Quota.Remaining != 2 || !slices.Equal(narrowed.Result.Grant, []string{"invoice.read"}) || primary.calls.Load() != 4 {
		t.Fatal("warm projection retained removed current authority", err)
	}
	for _, remaining := range []uint64{1, 0} {
		request.AttemptID = apikey.VerificationAttemptID(commandID(t))
		out, err := cache.VerifyAndConsume(f.ctx, request)
		if err != nil || out.Result == nil || out.Quota == nil || out.Quota.Remaining != remaining {
			t.Fatal("warm metadata replaced the actual remaining native quota", remaining, err)
		}
	}
	request.AttemptID = apikey.VerificationAttemptID(commandID(t))
	exhausted, err := cache.VerifyAndConsume(f.ctx, request)
	if !errors.Is(err, apikey.ErrDenied) || exhausted.Result != nil || exhausted.State != apikey.VerificationAttemptNotDebited || exhausted.Quota == nil || exhausted.Quota.Remaining != 0 || primary.calls.Load() != 7 {
		t.Fatal("warm positive bypassed native quota exhaustion", err)
	}
}

func TestNativePositiveCacheRevocationDeniesWarmKeyWithRemainingQuota(t *testing.T) {
	f := setupNativeConsumer(t)
	installQuota(t, f)
	c := quotaConfiguration(t, f.config, apikey.TokenBucketPolicy{Capacity: 2, RefillAmount: 1, RefillInterval: time.Hour})
	source, record, request := quotaKey(t, f, c)
	cache, primary := nativePositiveCache(t, f, c, source)
	warm, err := cache.VerifyAndConsume(f.ctx, request)
	if err != nil || warm.Result == nil || warm.Quota == nil || warm.Quota.Remaining != 1 {
		t.Fatal("revocation requires a genuine positive with spendable quota", err)
	}
	key, err := identity.NewIdempotencyKey([]byte("native-positive-cache-revoke"))
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := source.Revoke(f.ctx, apikey.Revocation{Authentication: f.caller, IdempotencyKey: key, KeyID: record.ID, ExpectedVersion: record.Version, Network: "192.0.2.1"})
	if err != nil || revoked.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual source revocation did not commit", err)
	}
	request.AttemptID = apikey.VerificationAttemptID(commandID(t))
	denied, err := cache.VerifyAndConsume(f.ctx, request)
	if err == nil || denied.Result != nil || primary.calls.Load() != 2 {
		t.Fatal("lost invalidation retained a revoked key principal", err)
	}
}

func TestNativePositiveCacheOwnerWithdrawalPreservesUnknownWithoutFallback(t *testing.T) {
	f := setupNativeConsumer(t)
	installQuota(t, f)
	c := quotaConfiguration(t, f.config, apikey.TokenBucketPolicy{Capacity: 2, RefillAmount: 1, RefillInterval: time.Hour})
	source, record, request := quotaKey(t, f, c)
	cache, primary := nativePositiveCache(t, f, c, source)
	original, err := cache.VerifyAndConsume(f.ctx, request)
	if err != nil || original.Result == nil || original.Quota == nil || original.Quota.Remaining != 1 {
		t.Fatal("genuine warm-owner precondition failed", err)
	}
	// Withdraw existing genuine authority; this is not an admin-workflow proof.
	changed, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.users SET status='suspended',version=version+1,authority_version=authority_version+1 WHERE tenant_id=$1 AND user_id=$2 AND status='active'`, baselineTenant, string(f.user))
	if err != nil || changed.RowsAffected() != 1 {
		t.Fatal("actual owner withdrawal failed", err)
	}
	request.AttemptID = apikey.VerificationAttemptID(commandID(t))
	denied, err := cache.VerifyAndConsume(f.ctx, request)
	var unknown apikey.ErrDebitOutcomeUnknown
	if !errors.As(err, &unknown) || denied.Validate() != nil || denied.State != apikey.VerificationAttemptPossibleDebit || denied.Outcome != identity.CommitOutcomeUnknown || denied.Result != nil || denied.Quota != nil || primary.calls.Load() != 2 {
		t.Fatal("warm cache hid current owner withdrawal or retried the source", err)
	}
	query := apikey.VerificationReconcileQuery{AttemptID: original.AttemptID, TenantID: baselineTenant, Fingerprint: original.Fingerprint, Original: original.Original}
	recovered, err := cache.ReconcileVerifyAndConsume(f.ctx, query)
	if !errors.As(err, &unknown) || recovered.Result != nil || recovered.Quota != nil || recovered.State != apikey.VerificationAttemptPossibleDebit || primary.calls.Load() != 2 {
		t.Fatal("historical inquiry authenticated from cache or repeated verification", err)
	}
	var balance string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT balance::text FROM identity_api_keys.quotas WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3`, baselineTenant, request.ConfigurationID, string(record.ID)).Scan(&balance); err != nil || balance != "3600000000" {
		t.Fatal("withdrawal or inquiry changed the original native debit", err)
	}
}
