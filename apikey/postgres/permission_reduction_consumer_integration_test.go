//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
)

const reductionActor = "api-key-policy-maintenance"
const reductionNamespace = "api-key-maintenance"

// This is the application's independently selected service-actor policy. It
// supplies no owner/key facts; the native Store must re-read and fence those.
type reductionConsumerPolicy struct {
	base   authorization.Service
	user   identity.UserID
	denied *atomic.Bool
	gate   *reductionPreparationGate
}

type reductionPreparationGate struct {
	armed, blocked   atomic.Bool
	calls            atomic.Int64
	entered, release chan struct{}
}

func (p reductionConsumerPolicy) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if p.gate != nil && p.gate.armed.Load() && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID == authorization.SubjectID(p.user) && r.Action == "invoice.read" && r.Resource.Type == "api-key" && r.Resource.ID == "automation" {
		p.gate.calls.Add(1)
		if p.gate.blocked.CompareAndSwap(false, true) {
			close(p.gate.entered)
			select {
			case <-p.gate.release:
			case <-ctx.Done():
				return authorization.Decision{}, ctx.Err()
			}
		}
	}
	if r.Subject.Kind != authorization.SubjectServiceAccount || r.Subject.ID != reductionActor {
		return p.base.Decide(ctx, authorization.DecisionContext{PolicyRevision: 9, Request: r})
	}
	allow := ctx.Err() == nil && !p.denied.Load() && r.Tenant == baselineTenant && r.Action == "identity.apikey.update"
	if allow {
		allow = r.Resource.Type == "identity.user" && r.Resource.ID == authorization.ResourceID(p.user) ||
			r.Resource.Type == "api-key" && r.Resource.ID == "automation" ||
			r.Resource.Type == "identity.request-admission" && r.Resource.ID == "identity.apikey.update"
	}
	if allow && r.Resource.Type == "api-key" {
		owner, ownerPresent := r.Resource.Attributes["api-key.owner-user-id"].String()
		configuration, configurationPresent := r.Resource.Attributes["api-key.configuration-id"].String()
		namespace, namespacePresent := r.Resource.Attributes["api-key.actor-policy-namespace"].String()
		allow = ownerPresent && owner == string(p.user) && configurationPresent && configuration == "automation" && namespacePresent && namespace == reductionNamespace
	}
	outcome := authorization.Deny
	if allow {
		outcome = authorization.Allow
	}
	return authorization.Decision{Outcome: outcome}, ctx.Err()
}

func setupReductionConsumer(t *testing.T, gate *reductionPreparationGate) (nativeConsumerFixture, apikeypg.ServiceConfig, *apikeypg.PermissionReductionStore, apikey.PermissionReductionDecision, *atomic.Bool) {
	t.Helper()
	f := setupNativeConsumer(t)
	var denied atomic.Bool
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "maintenance-consumer", Revision: 9, Evaluator: reductionConsumerPolicy{base: f.config.Authorization, user: f.user, denied: &denied, gate: gate}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	c := f.config
	c.Authorization = policy
	query, admission := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	query.Authorization, admission.Authorization = policy, policy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &admission
	c.RequestKeys.Policy.Authorization = policy
	primary, err := apikeypg.NewService(f.pool, c)
	if err != nil {
		t.Fatal("actual maintenance source composition failed", err)
	}
	if err := primary.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	binding := authenticatedSourceBinding(t, f, primary)
	f.deniedGrant.Store(true)
	t.Cleanup(func() { f.deniedGrant.Store(false) })
	observed, err := primary.ObserveSourceAuthority(f.ctx, binding)
	if err != nil || !slices.Equal(observed.Grant, []string{"invoice.read"}) {
		t.Fatal("real current policy did not remove permission", err)
	}
	current := apikey.CurrentAuthority{Owner: observed.Owner, OwnerActive: true, TenantActive: true, Permissions: slices.Clone(observed.Grant), PolicyVersion: observed.PolicyVersion, ConfigurationAuthority: observed.ConfigurationAuthority, ReadStartedAt: observed.ReadStartedAt, VerifiedAt: observed.VerifiedAt, ValidUntil: observed.ValidUntil}
	decision, err := (apikey.ScopePolicy{}).DecidePermissionReduction(commandID(t), observed.Record, current, c.Configuration, observed.VerifiedAt)
	if err != nil {
		t.Fatal("actual source did not yield a strict reduction", err)
	}
	actorScope := authority.AuthorityScope{TenantID: baselineTenant, PolicyNamespace: reductionNamespace, SubjectID: reductionActor}
	if _, err := authority.InitializeAuthority(f.ctx, f.pool.Raw(), actorScope, time.Second); err != nil {
		t.Fatal("actual service actor authority provisioning failed", err)
	}
	store, err := apikeypg.NewPermissionReductionStore(primary, apikeypg.PermissionReductionStoreConfig{TenantID: baselineTenant, UserID: f.user, ActorID: reductionActor, ActorPolicyNamespace: reductionNamespace})
	if err != nil {
		t.Fatal("fixed owner/service actor store rejected", err)
	}
	return f, c, store, decision, &denied
}

func TestNativePermissionReductionCurrentPolicyOriginalRetryAndActorWithdrawal(t *testing.T) {
	f, c, store, decision, denied := setupReductionConsumer(t, nil)

	for name, changed := range map[string]apikey.PermissionReductionDecision{"foreign-key-version": decision, "caller-expanded-current-policy": decision, "caller-invented-strict-removal": decision} {
		if name == "foreign-key-version" {
			changed.ExpectedKeyVersion++
		} else if name == "caller-invented-strict-removal" {
			changed.EffectiveCurrentGrant = []string{}
			changed.Grant = []string{}
		} else {
			changed.EffectiveCurrentGrant = slices.Clone(changed.PriorGrant)
			changed.Grant = slices.Clone(changed.PriorGrant)
		}
		changed.CommandID = commandID(t)
		out, err := store.ApplyPermissionReduction(f.ctx, changed)
		if err == nil || out.Record != nil || out.ConfigurationAuthority != nil {
			t.Fatal("caller decision became mutation authority", name)
		}
	}
	committed, err := store.ApplyPermissionReduction(f.ctx, decision)
	if err != nil || committed.Outcome != identity.CommitOutcomeCommitted || committed.Validate(c.Configuration) != nil || committed.Record == nil || committed.Record.AuthorityVersion != decision.ExpectedAuthorityVersion+1 || !slices.Equal(committed.Record.Grant, []string{"invoice.read"}) {
		t.Fatal("real policy reduction did not commit exact successor", err)
	}
	retry, err := store.ApplyPermissionReduction(f.ctx, decision)
	if err != nil || retry.Record == nil || retry.Record.Version != committed.Record.Version || retry.Record.AuthorityVersion != committed.Record.AuthorityVersion || retry.ConfigurationAuthority == nil || *retry.ConfigurationAuthority != *committed.ConfigurationAuthority {
		t.Fatal("exact original retry changed committed reduction", err)
	}
	denied.Store(true)
	withdrawn, err := store.ApplyPermissionReduction(f.ctx, decision)
	if !errors.Is(err, apikey.ErrDenied) || withdrawn.Record != nil || withdrawn.ConfigurationAuthority != nil {
		t.Fatal("withdrawn maintenance actor disclosed or reran original mutation", err)
	}
}

func TestNativePermissionReductionPendingOriginalHandleRecoveryAndWrongFingerprint(t *testing.T) {
	gate := &reductionPreparationGate{entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.release) }) }
	defer release()
	f, c, store, decision, _ := setupReductionConsumer(t, gate)
	ctx, cancel := context.WithTimeout(f.ctx, 8*time.Second)
	defer cancel()
	type result struct {
		out apikey.PermissionReductionResult
		err error
	}
	finished := make(chan result, 1)
	joined := false
	gate.armed.Store(true)
	go func() { out, err := store.ApplyPermissionReduction(ctx, decision); finished <- result{out, err} }()
	defer func() {
		release()
		if !joined {
			cancel()
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-finished:
			case <-timer.C:
				t.Error("owned original maintenance invocation did not stop")
			}
		}
	}()
	// The actual application policy is called outside SQL after the durable
	// generation start marker. Hold only that callback, not a copied journal or
	// invented lease, while an exact original retry reaches the real reservation.
	select {
	case <-gate.entered:
	case first := <-finished:
		joined = true
		t.Fatal("original never reached real preparation policy", first.err)
	case <-ctx.Done():
		t.Fatal("real preparation policy was not reached")
	}
	pending, err := store.ApplyPermissionReduction(ctx, decision)
	var lost apikey.PermissionReductionUnknownError
	if !errors.As(err, &lost) || lost.Recovery.Validate() != nil || lost.Recovery.CommandID != decision.CommandID || lost.Recovery.TenantID != baselineTenant || pending.Outcome != identity.CommitOutcomeInProgress && pending.Outcome != identity.CommitOutcomeUnknown || pending.Record != nil || pending.ConfigurationAuthority != nil {
		t.Fatal("real pending original lost captured recovery custody", err)
	}
	absent, err := store.ReconcilePermissionReduction(ctx, lost.Recovery)
	var unknown identity.UnknownCommitError
	if !errors.As(err, &unknown) || unknown.CommandID != decision.CommandID || absent.Record != nil || absent.ConfigurationAuthority != nil || absent.Decision.CommandID != "" {
		t.Fatal("pre-Apply absence fabricated original history or proved noncommit", err)
	}
	release()
	select {
	case first := <-finished:
		joined = true
		if first.err != nil || first.out.Validate(c.Configuration) != nil || first.out.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("actual original did not complete after policy release", first.err)
		}
	case <-ctx.Done():
		t.Fatal("released original did not finish")
	}
	recovered, err := store.ReconcilePermissionReduction(ctx, lost.Recovery)
	if err != nil || recovered.Validate(c.Configuration) != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Record == nil {
		t.Fatal("captured original query did not recover exact native effect", err)
	}
	wrong := lost.Recovery
	wrong.Fingerprint[0] ^= 0xff
	if out, err := store.ReconcilePermissionReduction(ctx, wrong); !errors.Is(err, apikey.ErrDenied) || out.Record != nil || out.ConfigurationAuthority != nil || out.Decision.CommandID != "" {
		t.Fatal("wrong original fingerprint disclosed retained metadata", err)
	}
	retry, err := store.ApplyPermissionReduction(ctx, decision)
	if err != nil || retry.Record == nil || retry.Record.AuthorityVersion != recovered.Record.AuthorityVersion || gate.calls.Load() != 1 {
		t.Fatal("original retry regenerated/re-evaluated preparation or advanced effect", err)
	}
}

func TestNativePermissionReductionMaximumEscapedGrantOriginalRetry(t *testing.T) {
	f, c, store, prior, _ := setupReductionConsumer(t, nil)
	primary, err := apikeypg.NewService(f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	// Use the root's count and permission-byte ceilings, with maximum JSON
	// escaping, and a real currently withdrawn permission to make it strict.
	f.deniedGrant.Store(false)
	permissions := append(slices.Clone(f.maximumGrants[:63]), "invoice.write")
	key, err := identity.NewIdempotencyKey([]byte("maintenance-maximum-original-create"))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := primary.Create(f.ctx, apikey.CreateRequest{Authentication: f.caller, IdempotencyKey: key, Name: strings.Repeat("&", 128), Permissions: permissions, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.55"})
	if err != nil {
		t.Fatal("maximum supported reduction source issuance", err)
	}
	record, ok := issued.Record()
	if !ok || !slices.Equal(record.Grant, permissions) {
		t.Fatal("maximum issued grant changed")
	}
	f.deniedGrant.Store(true)
	// Actual issuance metadata supplies structural input, not bearer authority.
	// The primary reader still validates current owner/key/config/policy facts.
	binding := apikey.SourceAuthorityBinding{ConfigurationAuthority: prior.ConfigurationAuthority, ConfigurationRevision: record.ConfigurationRevision, KeyID: record.ID, Owner: record.Owner, AuthorityVersion: record.AuthorityVersion, RootID: record.RootID, RootVersion: record.RootVersion, Issuer: record.Issuer, Environment: record.Environment, Audience: record.Audience, Grant: slices.Clone(record.Grant), ExpiresAt: record.ExpiresAt}
	observed, err := primary.ObserveSourceAuthority(f.ctx, binding)
	if err != nil {
		t.Fatal("maximum actual current source observation", err)
	}
	current := apikey.CurrentAuthority{Owner: observed.Owner, OwnerActive: true, TenantActive: true, Permissions: slices.Clone(observed.Grant), PolicyVersion: observed.PolicyVersion, ConfigurationAuthority: observed.ConfigurationAuthority, ReadStartedAt: observed.ReadStartedAt, VerifiedAt: observed.VerifiedAt, ValidUntil: observed.ValidUntil}
	decision, err := (apikey.ScopePolicy{}).DecidePermissionReduction(commandID(t), observed.Record, current, c.Configuration, observed.VerifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := store.ApplyPermissionReduction(f.ctx, decision)
	if err != nil || committed.Validate(c.Configuration) != nil || committed.Outcome != identity.CommitOutcomeCommitted || !slices.Equal(committed.Record.Grant, permissions[:63]) {
		t.Fatal("maximum original preparation could not commit", err)
	}
	retry, err := store.ApplyPermissionReduction(f.ctx, decision)
	if err != nil || retry.Validate(c.Configuration) != nil || retry.Record.Version != committed.Record.Version || retry.Record.AuthorityVersion != committed.Record.AuthorityVersion || !slices.Equal(retry.Record.Grant, committed.Record.Grant) || *retry.ConfigurationAuthority != *committed.ConfigurationAuthority {
		t.Fatal("maximum original retry failed to restore exact retained preparation", err)
	}
}
