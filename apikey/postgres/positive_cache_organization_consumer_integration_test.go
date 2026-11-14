//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	apikeyvalkey "github.com/faustbrian/go-identity/apikey/valkey"
	"github.com/faustbrian/go-identity/reference"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// This is caller-supplied service policy, not a fake organization/key authority.
// The Store must independently read and fence its fixed organization and actor.
type organizationMaintenancePolicy struct {
	base         authorization.Service
	organization organization.ID
	gate         *reductionPreparationGate
}

func (p organizationMaintenancePolicy) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if p.gate != nil && p.gate.armed.Load() && r.Subject.Kind == authorization.SubjectAPIKey && r.Resource.Type == "organization-api-key" && r.Resource.ID == authorization.ResourceID(p.organization) && r.Action == "invoice.read" && p.gate.blocked.CompareAndSwap(false, true) {
		close(p.gate.entered)
		select {
		case <-p.gate.release:
		case <-ctx.Done():
			return authorization.Decision{}, ctx.Err()
		}
	}
	if r.Subject.Kind != authorization.SubjectServiceAccount || r.Subject.ID != reductionActor {
		return p.base.Decide(ctx, authorization.DecisionContext{PolicyRevision: 9, Request: r})
	}
	allowed := ctx.Err() == nil && r.Tenant == baselineTenant && r.Action == "identity.apikey.update"
	if allowed {
		switch r.Resource.Type {
		case "organization-api-key":
			org, orgOK := r.Resource.Attributes["api-key.owner-organization-id"].String()
			namespace, namespaceOK := r.Resource.Attributes["api-key.actor-policy-namespace"].String()
			allowed = r.Resource.ID == authorization.ResourceID(p.organization) && orgOK && org == string(p.organization) && namespaceOK && namespace == reductionNamespace
		case "identity.anonymous-flow":
			_, err := identity.ParseCommandID(string(r.Resource.ID))
			allowed = err == nil
		case "identity.request-admission":
			allowed = r.Resource.ID == "identity.apikey.update"
		default:
			allowed = false
		}
	}
	outcome := authorization.Deny
	if allowed {
		outcome = authorization.Allow
	}
	return authorization.Decision{Outcome: outcome}, ctx.Err()
}

type organizationCacheFixture struct {
	native        nativeConsumerFixture
	configuration apikeypg.ServiceConfig
	organization  *organizationpg.Service
	repository    *organizationpg.Repository
	id            organization.ID
	manager       apikey.Authentication
	primary       *apikeypg.Service
	store         *apikeypg.PermissionReductionStore
	record        apikey.Record
	request       apikey.AtomicVerificationRequest
	gate          *reductionPreparationGate
}

func setupOrganizationCache(t *testing.T, capacity uint64) organizationCacheFixture {
	t.Helper()
	f := setupNativeConsumerWithMigrationBatches(t, [][]reference.ModuleID{
		{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres"},
		{"audit/postgres", "outbox/postgres", "outbox/postgres/identity"},
		{"rate-limit/postgres", "identity/password/postgres", "identity/mfa/postgres", "capability/postgres/identity"},
	})
	installOrganizationKeyOwners(t, f)
	installQuota(t, f)
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	org, repository, config := organizationKeyOwners(t, f, organization.ID(id))
	create, err := org.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: organization.Authentication{TenantID: f.caller.TenantID, Bearer: f.caller.Bearer}, CommandID: commandID(t), ID: organization.ID(id), Slug: "organization-positive-cache", Name: "Organization projection owner", CorrelationID: "org-cache-create"}, "192.0.2.21")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := org.Execute(f.ctx, create); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual organization cache owner creation failed", err)
	}
	manager, managerID := f.register()
	add, err := org.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: organization.Authentication{TenantID: f.caller.TenantID, Bearer: f.caller.Bearer}, CommandID: commandID(t), OrganizationID: organization.ID(id), UserID: managerID, Role: organization.RoleOwner, OrganizationVersion: 1, CorrelationID: "org-cache-manager"}, "192.0.2.21")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := org.Execute(f.ctx, add); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual second organization manager admission failed", err)
	}
	config = quotaConfiguration(t, config, apikey.TokenBucketPolicy{Capacity: capacity, RefillAmount: 1, RefillInterval: time.Hour})
	gate := &reductionPreparationGate{entered: make(chan struct{}), release: make(chan struct{})}
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "organization-maintenance", Revision: 9, Evaluator: organizationMaintenancePolicy{base: config.Authorization, organization: organization.ID(id), gate: gate}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	config.Authorization, err = authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	query, admission := *config.Coordinator.QueryPolicy, *config.Coordinator.AdmissionPolicy
	query.Authorization, admission.Authorization = config.Authorization, config.Authorization
	config.Coordinator.QueryPolicy, config.Coordinator.AdmissionPolicy = &query, &admission
	primary, err := apikeypg.NewOrganizationService(f.pool, config, repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	key, _ := identity.NewIdempotencyKey([]byte("org-cache-key-" + string(id)))
	issued, err := primary.CreateOrganization(f.ctx, apikey.OrganizationCreateRequest{CreateRequest: apikey.CreateRequest{Authentication: f.caller, IdempotencyKey: key, Name: "organization positive metadata", Permissions: []string{"invoice.read", "invoice.write"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.21"}, OrganizationID: apikey.OrganizationID(id)})
	if err != nil {
		t.Fatal("actual finite organization key issuance failed", err)
	}
	record, ok := issued.Record()
	if !ok || record.Owner.Spec().UserID != "" || record.Owner.Spec().OrganizationID != apikey.OrganizationID(id) {
		t.Fatal("organization key borrowed a human owner")
	}
	wire, err := issued.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := apikey.ParseSecret(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.InitializeAuthority(f.ctx, f.pool.Raw(), authority.AuthorityScope{TenantID: baselineTenant, PolicyNamespace: reductionNamespace, SubjectID: reductionActor}, time.Second); err != nil {
		t.Fatal("actual independent maintenance actor authority failed", err)
	}
	store, err := apikeypg.NewOrganizationPermissionReductionStore(primary, apikeypg.OrganizationPermissionReductionStoreConfig{TenantID: baselineTenant, OrganizationID: apikey.OrganizationID(id), ActorID: reductionActor, ActorPolicyNamespace: reductionNamespace})
	if err != nil {
		t.Fatal("genuine organization Store composition failed", err)
	}
	request := apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: config.Configuration.Spec().ID, ConfigurationRevision: config.Configuration.Spec().Revision, Candidate: record.ID, Secret: secret, RequiredPermissions: []string{"invoice.read"}, DebitAmount: 1}
	return organizationCacheFixture{native: f, configuration: config, organization: org, repository: repository, id: organization.ID(id), manager: manager, primary: primary, store: store, record: record, request: request, gate: gate}
}

func TestNativeOrganizationPositiveCacheStoreOriginalReductionRecovery(t *testing.T) {
	proveOrganizationStoreOriginalPreparation(t, "commit")
}

func TestNativeOrganizationPositiveCacheStoreActorEpochWithdrawal(t *testing.T) {
	proveOrganizationStoreOriginalPreparation(t, "actor-epoch-withdrawal")
}

func proveOrganizationStoreOriginalPreparation(t *testing.T, outcome string) {
	t.Helper()
	f := setupOrganizationCache(t, 3)
	cache, primary := organizationPositiveCache(t, f)
	verified, err := cache.VerifyAndConsume(f.native.ctx, f.request)
	if err != nil || verified.Result == nil {
		t.Fatal("real organization key required before native maintenance", err)
	}
	binding, err := apikey.NewOrganizationSourceAuthorityBinding(*verified.Result, f.configuration.Configuration, verified.Result.VerifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	f.native.deniedGrant.Store(true)
	observed, err := f.primary.ObserveOrganizationSourceAuthority(f.native.ctx, binding)
	if err != nil || !slices.Equal(observed.Grant, []string{"invoice.read"}) {
		t.Fatal("actual current organization policy did not narrow", err)
	}
	current := apikey.CurrentAuthority{Owner: observed.Owner, OwnerActive: true, TenantActive: true, Permissions: slices.Clone(observed.Grant), PolicyVersion: observed.PolicyVersion, ConfigurationAuthority: observed.ConfigurationAuthority, ReadStartedAt: observed.ReadStartedAt, VerifiedAt: observed.VerifiedAt, ValidUntil: observed.ValidUntil}
	decision, err := (apikey.ScopePolicy{}).DecidePermissionReduction(commandID(t), observed.Record, current, f.configuration.Configuration, observed.VerifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	var originalRecord []byte
	if err := f.native.pool.Raw().QueryRow(f.native.ctx, `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3`, baselineTenant, f.request.ConfigurationID, string(f.record.ID)).Scan(&originalRecord); err != nil {
		t.Fatal("actual organization record snapshot missing", err)
	}
	foreign := decision
	owner := decision.Owner.Spec()
	owner.OrganizationID = "another-organization"
	foreign.Owner, err = apikey.NewOwner(owner)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := cache.ApplyPermissionReduction(f.native.ctx, foreign); err == nil || out.Record != nil {
		t.Fatal("native organization Store accepted a different owner")
	}
	type answer struct {
		out apikey.PermissionReductionResult
		err error
	}
	completed := make(chan answer, 1)
	f.gate.armed.Store(true)
	ctx, stop := context.WithTimeout(f.native.ctx, 12*time.Second)
	defer stop()
	started := time.Now()
	go func() {
		out, err := cache.ApplyPermissionReduction(ctx, decision)
		completed <- answer{out: out, err: err}
	}()
	released := false
	defer func() {
		if !released {
			close(f.gate.release)
			<-completed
		}
	}()
	select {
	case <-f.gate.entered:
	case early := <-completed:
		close(f.gate.release)
		released = true
		t.Fatal("native organization preparation did not reach actual current-policy callback", early.err)
	case <-ctx.Done():
		t.Fatal("native organization preparation did not reach bounded callback", ctx.Err())
	}
	pending, err := cache.ApplyPermissionReduction(ctx, decision)
	var original apikey.PermissionReductionUnknownError
	if !errors.As(err, &original) || original.Recovery.Validate() != nil || original.Recovery.CommandID != decision.CommandID || original.Recovery.TenantID != baselineTenant || pending.Validate(f.configuration.Configuration) != nil || pending.Record != nil || pending.ConfigurationAuthority != nil || pending.Outcome != identity.CommitOutcomeUnknown && pending.Outcome != identity.CommitOutcomeInProgress {
		t.Fatal("pending organization maintenance lost actual original handle", pending.Outcome, err)
	}
	if out, err := cache.ReconcilePermissionReduction(ctx, original.Recovery); err == nil || out.Record != nil || out.ConfigurationAuthority != nil {
		t.Fatal("absent pre-Apply effect fabricated organization commitment")
	}
	if outcome == "actor-epoch-withdrawal" {
		policies, err := authority.NewAuthorityStore(f.native.pool.Raw(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		scope := authority.AuthorityScope{TenantID: baselineTenant, PolicyNamespace: reductionNamespace, SubjectID: reductionActor}
		before, err := policies.Get(ctx, scope)
		if err != nil {
			t.Fatal("actual maintenance actor epoch missing", err)
		}
		tx, err := f.native.pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		after, err := authority.AdvanceAuthority(ctx, tx, scope, before.Version, time.Second)
		if err != nil || after.Version != before.Version+1 {
			t.Fatal("actual maintenance actor epoch was not withdrawn", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal("actual maintenance actor withdrawal did not commit", err)
		}
	}
	close(f.gate.release)
	released = true
	result := <-completed
	if outcome == "actor-epoch-withdrawal" {
		if result.err == nil || errors.Is(result.err, context.Canceled) || errors.Is(result.err, context.DeadlineExceeded) || time.Since(started) >= f.configuration.MaximumDuration || result.out.Outcome == identity.CommitOutcomeCommitted || result.out.Record != nil || result.out.ConfigurationAuthority != nil || primary.calls.Load() != 1 {
			t.Fatal("withdrawn actual actor epoch committed, timed out or repeated verification", result.err)
		}
		assertStoredKeyState(t, f.native.ctx, f.native.pool, baselineTenant, f.record.ID, apikey.KeyActive, f.record.Version, f.record.AuthorityVersion)
		var retainedRecord []byte
		if err := f.native.pool.Raw().QueryRow(f.native.ctx, `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3`, baselineTenant, f.request.ConfigurationID, string(f.record.ID)).Scan(&retainedRecord); err != nil || !bytes.Equal(retainedRecord, originalRecord) {
			t.Fatal("withdrawn actor changed the original key record", err)
		}
		var configurationVersion string
		if err := f.native.pool.Raw().QueryRow(f.native.ctx, `SELECT authority_version::text FROM identity_api_keys.configurations WHERE tenant_id=$1 AND configuration_id=$2`, baselineTenant, f.request.ConfigurationID).Scan(&configurationVersion); err != nil || configurationVersion != strconv.FormatUint(decision.ConfigurationAuthority.Version, 10) {
			t.Fatal("withdrawn actor advanced configuration authority", err)
		}
		var effects int
		if err := f.native.pool.Raw().QueryRow(f.native.ctx, `SELECT count(*) FROM identity_api_keys.command_effects WHERE command_id=$1 AND tenant_id=$2`, string(decision.CommandID), baselineTenant).Scan(&effects); err != nil || effects != 0 {
			t.Fatal("withdrawn actor retained a key permission effect", err)
		}
		return
	}
	if result.err != nil || result.out.Record == nil || result.out.Outcome != identity.CommitOutcomeCommitted || !slices.Equal(result.out.Record.Grant, []string{"invoice.read"}) {
		t.Fatal("actual original organization reduction did not commit", result.err)
	}
	recovered, err := cache.ReconcilePermissionReduction(ctx, original.Recovery)
	if err != nil || recovered.Record == nil || recovered.Record.Version != result.out.Record.Version || recovered.Record.AuthorityVersion != result.out.Record.AuthorityVersion {
		t.Fatal("organization Store could not reconcile exact original commitment", err)
	}
	wrong := original.Recovery
	wrong.Fingerprint[0] ^= 1
	if out, err := cache.ReconcilePermissionReduction(ctx, wrong); err == nil || out.Record != nil || out.ConfigurationAuthority != nil {
		t.Fatal("wrong original fingerprint disclosed organization maintenance")
	}
	retry, err := cache.ApplyPermissionReduction(ctx, decision)
	if err != nil || retry.Record == nil || retry.Record.Version != result.out.Record.Version || retry.Record.AuthorityVersion != result.out.Record.AuthorityVersion || primary.calls.Load() != 1 {
		t.Fatal("original organization reduction retry re-decided or reverified", err)
	}
	request := f.request
	request.AttemptID = apikey.VerificationAttemptID(commandID(t))
	if out, err := cache.VerifyAndConsume(f.native.ctx, request); err != nil || out.Result == nil || out.Quota == nil || out.Quota.Remaining != 1 || !slices.Equal(out.Result.Grant, []string{"invoice.read"}) {
		t.Fatal("real organization metadata consumer did not adopt committed reduction", err)
	}
}

func TestNativeOrganizationPositiveCacheRevokedRootAndArchivedOwnerDeny(t *testing.T) {
	for _, mode := range []string{"revoke", "archive"} {
		t.Run(mode, func(t *testing.T) {
			f := setupOrganizationCache(t, 3)
			cache, primary := organizationPositiveCache(t, f)
			warm, err := cache.VerifyAndConsume(f.native.ctx, f.request)
			if err != nil || warm.Result == nil || warm.Quota == nil || warm.Quota.Remaining != 2 {
				t.Fatal("actual spendable warm organization key missing", err)
			}
			withdrawnAt := time.Now()
			if mode == "revoke" {
				key, _ := identity.NewIdempotencyKey([]byte("warm-organization-cache-revoke"))
				if out, err := f.primary.Revoke(f.native.ctx, apikey.Revocation{Authentication: f.manager, IdempotencyKey: key, KeyID: f.record.ID, ExpectedVersion: f.record.Version, Network: "192.0.2.22"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("actual organization key revoke failed", err)
				}
			} else {
				// The owner supports archive, not a separate suspension state. This
				// injects that genuine primary withdrawal, not a public admin claim.
				if tag, err := f.native.pool.Raw().Exec(f.native.ctx, `UPDATE organization.organizations SET state='archived',version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND state='active'`, baselineTenant, string(f.id)); err != nil || tag.RowsAffected() != 1 {
					t.Fatal("actual primary organization withdrawal failed", err)
				}
			}
			request := f.request
			request.AttemptID = apikey.VerificationAttemptID(commandID(t))
			denied, err := cache.VerifyAndConsume(f.native.ctx, request)
			if err == nil || denied.Result != nil || primary.calls.Load() != 2 || time.Since(withdrawnAt) >= 30*time.Second {
				t.Fatal("warm cache ignored actual current owner/root withdrawal", err)
			}
			query := apikey.VerificationReconcileQuery{AttemptID: warm.AttemptID, TenantID: baselineTenant, Fingerprint: warm.Fingerprint, Original: warm.Original}
			if history, err := cache.ReconcileVerifyAndConsume(f.native.ctx, query); err == nil && history.Result != nil || primary.calls.Load() != 2 {
				t.Fatal("withdrawn owner history acquired a cache principal or reverified", err)
			}
			if mode == "archive" {
				if tag, err := f.native.pool.Raw().Exec(f.native.ctx, `UPDATE organization.organizations SET state='active',version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND state='archived'`, baselineTenant, string(f.id)); err != nil || tag.RowsAffected() != 1 {
					t.Fatal("actual primary organization restoration failed", err)
				}
				request.AttemptID = apikey.VerificationAttemptID(commandID(t))
				if out, err := cache.VerifyAndConsume(f.native.ctx, request); err == nil || out.Result != nil {
					t.Fatal("archive/restore resurrected withdrawn organization credential epoch", err)
				}
			}
			var balance string
			if err := f.native.pool.Raw().QueryRow(f.native.ctx, `SELECT balance::text FROM identity_api_keys.quotas WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3`, baselineTenant, f.request.ConfigurationID, string(f.record.ID)).Scan(&balance); err != nil || balance != "7200000000" {
				t.Fatal("withdrawal/reconciliation spent another actual native token", err)
			}
		})
	}
}

func TestNativeOrganizationPositiveCacheLostCommitAndRequiredEffectRollback(t *testing.T) {
	f := setupOrganizationCache(t, 3)
	cache, primary := organizationPositiveCache(t, f)
	original, err := cache.VerifyAndConsume(f.native.ctx, f.request)
	if err != nil || original.Result == nil || original.Quota == nil || original.Quota.Remaining != 2 {
		t.Fatal("warm actual organization source missing", err)
	}
	request := f.request
	request.AttemptID = apikey.VerificationAttemptID(commandID(t))
	if _, err := f.native.pool.Raw().Exec(f.native.ctx, `CREATE FUNCTION public.reject_org_cache_auth_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='identity.api_key.authenticate' AND NEW.outcome=1 THEN RAISE EXCEPTION 'injected required audit outage'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_org_cache_auth_audit BEFORE INSERT ON audit.records FOR EACH ROW EXECUTE FUNCTION public.reject_org_cache_auth_audit()`); err != nil {
		t.Fatal("organization verification effect fault setup", err)
	}
	failed, verifyErr := cache.VerifyAndConsume(f.native.ctx, request)
	if _, err := f.native.pool.Raw().Exec(f.native.ctx, `DROP TRIGGER reject_org_cache_auth_audit ON audit.records; DROP FUNCTION public.reject_org_cache_auth_audit()`); err != nil {
		t.Fatal("organization verification effect fault cleanup", err)
	}
	if verifyErr == nil || failed.Result != nil || failed.Validate() != nil || failed.State != apikey.VerificationAttemptNotDebited || failed.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("warm metadata bypassed required native verification effect rollback", verifyErr)
	}
	if primary.calls.Load() != 2 {
		t.Fatal("rollback repeated native verification")
	}
	fault := &legacyCommitFault{marker: []byte("INSERT INTO identity_api_keys.command_effects")}
	pool, err := database.Connect(f.native.ctx, database.Config{DSN: f.native.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.native.pool.Raw().Config().ConnConfig.Database
		c.ConnConfig.DialFunc = fault.dial
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("exact owned organization fault-pool cleanup", err)
		}
	})
	faultSource, err := apikeypg.NewOrganizationService(pool, f.configuration, f.repository)
	if err != nil {
		t.Fatal(err)
	}
	// Change only the native verifier's owned transport, after a real cache fill.
	// The source implementation, primary data, original attempt and cache stay real.
	primary.source = faultSource
	request.AttemptID = apikey.VerificationAttemptID(commandID(t))
	unknown, err := cache.VerifyAndConsume(f.native.ctx, request)
	primary.source = f.primary
	var lost apikey.ErrDebitOutcomeUnknown
	if !errors.As(err, &lost) || !fault.hit.Load() || unknown.Validate() != nil || unknown.State != apikey.VerificationAttemptPossibleDebit || unknown.Result != nil || unknown.Quota != nil || primary.calls.Load() != 3 || unknown.Fingerprint == ([32]byte{}) {
		t.Fatal("cache hid original uncertain native organization debit or retried", err)
	}
	query := apikey.VerificationReconcileQuery{AttemptID: unknown.AttemptID, TenantID: baselineTenant, Fingerprint: unknown.Fingerprint, Original: unknown.Original}
	var recovered apikey.AtomicVerificationResult
	deadline := time.Now().Add(8 * time.Second)
	for {
		recovered, err = cache.ReconcileVerifyAndConsume(f.native.ctx, query)
		if err == nil && recovered.State == apikey.VerificationAttemptDebited {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("original uncertain organization debit did not reconcile", err)
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-f.native.ctx.Done():
			t.Fatal("original organization recovery canceled", f.native.ctx.Err())
		}
	}
	if err != nil || recovered.Result == nil || recovered.Quota == nil || recovered.Quota.Remaining != 1 || recovered.Fingerprint != unknown.Fingerprint || recovered.Original != unknown.Original || primary.calls.Load() != 3 {
		t.Fatal("exact original organization reconciliation replaced scope or spent again", err)
	}
	wrong := query
	wrong.Fingerprint[0] ^= 1
	if out, err := cache.ReconcileVerifyAndConsume(f.native.ctx, wrong); err == nil || out.Result != nil || out.Quota != nil {
		t.Fatal("wrong original fingerprint acquired organization quota history")
	}
	retry, err := cache.VerifyAndConsume(f.native.ctx, request)
	if err != nil || retry.Result == nil || retry.Quota == nil || *retry.Quota != *recovered.Quota || retry.Fingerprint != recovered.Fingerprint || retry.Result.ValidUntil.After(recovered.Result.ValidUntil) || primary.calls.Load() != 4 {
		t.Fatal("matching uncertain organization retry debited again or renewed evidence", err)
	}
}

func TestNativeOrganizationPositiveCachePrimaryAuthorityOutageCannotFallback(t *testing.T) {
	f := setupOrganizationCache(t, 3)
	cache, primary := organizationPositiveCache(t, f)
	original, err := cache.VerifyAndConsume(f.native.ctx, f.request)
	if err != nil || original.Result == nil || original.Quota == nil || original.Quota.Remaining != 2 {
		t.Fatal("actual warm organization authority missing", err)
	}
	// Close only this test's genuine native pool after a real cache fill. The
	// independent SQL connection below observes state but supplies no authority.
	if err := f.native.pool.Close(f.native.ctx); err != nil {
		t.Fatal("owned primary-authority outage setup failed", err)
	}
	request := f.request
	request.AttemptID = apikey.VerificationAttemptID(commandID(t))
	denied, err := cache.VerifyAndConsume(f.native.ctx, request)
	if err == nil || denied.Result != nil || denied.Quota != nil || primary.calls.Load() != 2 {
		t.Fatal("warm organization cache replaced unavailable genuine primary authority", err)
	}
	query := apikey.VerificationReconcileQuery{AttemptID: original.AttemptID, TenantID: baselineTenant, Fingerprint: original.Fingerprint, Original: original.Original}
	history, err := cache.ReconcileVerifyAndConsume(f.native.ctx, query)
	if err == nil || history.Result != nil || history.Quota != nil || primary.calls.Load() != 2 {
		t.Fatal("unavailable original inquiry fabricated a cached organization principal", err)
	}
	var balance string
	if err := f.native.db.QueryRowContext(f.native.ctx, `SELECT balance::text FROM identity_api_keys.quotas WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3`, baselineTenant, f.request.ConfigurationID, string(f.record.ID)).Scan(&balance); err != nil || balance != "7200000000" {
		t.Fatal("primary outage or original reconciliation spent cached quota", err)
	}
}

func organizationPositiveCache(t *testing.T, f organizationCacheFixture) (*apikeyvalkey.Cache, *countedCachePrimary) {
	t.Helper()
	trust, err := os.ReadFile(os.Getenv("APIKEY_VALKEY_CA_FILE"))
	if err != nil {
		t.Fatal("explicit owned Valkey trust required")
	}
	password, err := os.ReadFile(os.Getenv("APIKEY_VALKEY_PASSWORD_FILE"))
	if err != nil {
		t.Fatal("explicit owned Valkey authentication required")
	}
	credential, err := apikeyvalkey.NewSecret(password)
	clear(password)
	if err != nil {
		t.Fatal("Valkey credential rejected")
	}
	var namespace [32]byte
	if _, err := rand.Read(namespace[:]); err != nil {
		t.Fatal(err)
	}
	namespaceKey, err := apikeyvalkey.NewSecret(namespace[:])
	clear(namespace[:])
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keyring.New(f.configuration.RetainedEnvelopeKeys)
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	primary := &countedCachePrimary{source: f.primary}
	cache, err := apikeyvalkey.NewOrganization(f.native.ctx, apikeyvalkey.Config{Profile: "positive-projection", Topology: "standalone", Endpoint: os.Getenv("APIKEY_VALKEY_ENDPOINT"), Username: "default", Password: credential, NamespaceKey: namespaceKey, TrustPEM: trust, MaximumDuration: 4 * time.Second, CacheTimeout: 250 * time.Millisecond, MaximumConcurrent: 4, MaximumPayloadBytes: 65536}, apikey.PositiveProjectionConfig{Configuration: f.configuration.Configuration, TenantID: baselineTenant, Store: f.store, Verifier: primary, Crypto: crypto, Clock: f.configuration.Clock, Namespace: "org-native-" + string(commandID(t)), DeploymentEpoch: 1, KeyReference: f.configuration.ActiveEnvelopeKeyID, MaximumDuration: 4 * time.Second, MaximumBytes: 65536}, f.primary)
	if err != nil {
		t.Fatal("real organization/native/TLS-Valkey composition failed", err)
	}
	t.Cleanup(cache.Close)
	return cache, primary
}

func TestNativeOrganizationPositiveCacheCreatorRemovalQuotaAndNarrowing(t *testing.T) {
	f := setupOrganizationCache(t, 6)
	cache, primary := organizationPositiveCache(t, f)
	original, err := cache.VerifyAndConsume(f.native.ctx, f.request)
	if err != nil || original.Result == nil || original.Quota == nil || original.Quota.Remaining != 5 || original.Result.Owner.Spec().UserID != "" || primary.calls.Load() != 1 {
		t.Fatal("cold organization cache did not preserve actual native credential/debit", err)
	}
	request := f.request
	request.AttemptID = apikey.VerificationAttemptID(commandID(t))
	warm, err := cache.VerifyAndConsume(f.native.ctx, request)
	if err != nil || warm.Result == nil || warm.Quota == nil || warm.Quota.Remaining != 4 || warm.Result.ValidUntil.After(original.Result.ValidUntil) || primary.calls.Load() != 2 {
		remaining, extended := uint64(0), false
		if warm.Quota != nil {
			remaining = warm.Quota.Remaining
		}
		if warm.Result != nil {
			extended = warm.Result.ValidUntil.After(original.Result.ValidUntil)
		}
		t.Fatalf("warm organization invariant: error=%v principal=%t quota=%t remaining=%d calls=%d extended=%t original_age=%s original_remaining=%s", err, warm.Result != nil, warm.Quota != nil, remaining, primary.calls.Load(), extended, time.Since(original.Result.ReadStartedAt), time.Until(original.Result.ValidUntil))
	}
	retry, err := cache.VerifyAndConsume(f.native.ctx, f.request)
	if err != nil || retry.Result == nil || retry.Quota == nil || *retry.Quota != *original.Quota || retry.Fingerprint != original.Fingerprint || retry.Original != original.Original || retry.Result.ValidUntil.After(original.Result.ValidUntil) || primary.calls.Load() != 3 {
		t.Fatal("exact organization retry replaced original custody or spent again", err)
	}
	remove, err := f.organization.PrepareRemoveMember(f.native.ctx, organization.MemberRequest{Authentication: organization.Authentication{TenantID: f.manager.TenantID, Bearer: f.manager.Bearer}, CommandID: commandID(t), OrganizationID: f.id, UserID: f.native.user, OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "org-cache-remove-creator"}, "192.0.2.22")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := f.organization.Execute(f.native.ctx, remove); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual creator membership removal failed", err)
	}
	updateKey, _ := identity.NewIdempotencyKey([]byte("removed-cache-creator-management"))
	if _, err := f.primary.Update(f.native.ctx, apikey.UpdateRequest{Authentication: f.native.caller, IdempotencyKey: updateKey, OrganizationID: apikey.OrganizationID(f.id), KeyID: f.record.ID, ExpectedVersion: f.record.Version, Name: "forbidden creator", Permissions: slices.Clone(f.record.Grant), Network: "192.0.2.22"}); err == nil {
		t.Fatal("removed creator retained human management via cache ownership")
	}
	request.AttemptID = apikey.VerificationAttemptID(commandID(t))
	surviving, err := cache.VerifyAndConsume(f.native.ctx, request)
	if err != nil || surviving.Result == nil || surviving.Quota == nil || surviving.Quota.Remaining != 3 || surviving.Result.Owner != f.record.Owner {
		t.Fatal("creator removal revoked genuine integration ownership", err)
	}
	f.native.deniedGrant.Store(true)
	request.AttemptID = apikey.VerificationAttemptID(commandID(t))
	narrowed, err := cache.VerifyAndConsume(f.native.ctx, request)
	if err != nil || narrowed.Result == nil || narrowed.Quota == nil || narrowed.Quota.Remaining != 2 || !slices.Equal(narrowed.Result.Grant, []string{"invoice.read"}) {
		t.Fatal("warm org metadata preserved withdrawn current grant", err)
	}
	f.native.deniedGrant.Store(false)
	request.RequiredPermissions, request.AttemptID = []string{"invoice.write"}, apikey.VerificationAttemptID(commandID(t))
	if out, err := cache.VerifyAndConsume(f.native.ctx, request); !errors.Is(err, apikey.ErrDenied) || out.Result != nil || out.State == apikey.VerificationAttemptDebited {
		t.Fatal("restored policy/cache re-expanded immutable organization grant", err)
	}
	request.RequiredPermissions = []string{"invoice.read"}
	for _, remaining := range []uint64{1, 0} {
		request.AttemptID = apikey.VerificationAttemptID(commandID(t))
		if out, err := cache.VerifyAndConsume(f.native.ctx, request); err != nil || out.Result == nil || out.Quota == nil || out.Quota.Remaining != remaining {
			t.Fatal("organization metadata bypassed actual native quota", err)
		}
	}
	request.AttemptID = apikey.VerificationAttemptID(commandID(t))
	if out, err := cache.VerifyAndConsume(f.native.ctx, request); !errors.Is(err, apikey.ErrDenied) || out.Result != nil || out.State != apikey.VerificationAttemptNotDebited || out.Quota == nil || out.Quota.Remaining != 0 || primary.calls.Load() != 9 {
		t.Fatal("warm organization metadata bypassed quota exhaustion", err)
	}
}
