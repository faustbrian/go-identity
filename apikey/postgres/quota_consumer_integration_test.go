//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	database "github.com/faustbrian/go-postgres"
)

func quotaConfiguration(t *testing.T, c apikeypg.ServiceConfig, policy apikey.TokenBucketPolicy) apikeypg.ServiceConfig {
	t.Helper()
	spec := c.Configuration.Spec()
	spec.ID, spec.Quota, spec.TokenBucket = "rotation", apikey.QuotaTokenBucket, policy
	var err error
	c.Configuration, err = apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func installQuota(t *testing.T, f nativeConsumerFixture) {
	t.Helper()
	steps, err := (apikeypg.QuotaMigrationSource{Version: 7101}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := migrationpg.New(f.db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("identity_api_key_quotas")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(migrationList(steps), backend)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := runner.Up(f.ctx); err != nil || len(out.Records()) != 1 {
		t.Fatal("optional quota schema installation", err)
	}
	if out, err := runner.Up(f.ctx); err != nil || len(out.Records()) != 0 {
		t.Fatal("optional quota migration changed installed history", err)
	}
}

func quotaKey(t *testing.T, f nativeConsumerFixture, c apikeypg.ServiceConfig) (*apikeypg.Service, apikey.Record, apikey.AtomicVerificationRequest) {
	t.Helper()
	s, err := apikeypg.NewService(f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	key, _ := identity.NewIdempotencyKey([]byte("quota-key-create-" + c.Configuration.Spec().ID))
	issued, err := s.Create(f.ctx, apikey.CreateRequest{Authentication: f.caller, IdempotencyKey: key, Name: "quota", Permissions: []string{"invoice.read", "invoice.write"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.1"})
	if err != nil {
		t.Fatal("real finite-key issuance", err)
	}
	record, ok := issued.Record()
	if !ok {
		t.Fatal("issued key metadata absent")
	}
	wire, err := issued.Reveal()
	if err != nil {
		t.Fatal("known committed quota key not delivered")
	}
	secret, _ := apikey.ParseSecret(wire)
	r := apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: c.Configuration.Spec().ID, ConfigurationRevision: c.Configuration.Spec().Revision, Candidate: record.ID, Secret: secret, RequiredPermissions: []string{"invoice.read"}, DebitAmount: 1}
	return s, record, r
}

func TestNativeQuotaExhaustionReplayAndOriginalAuthority(t *testing.T) {
	f := setupNativeConsumer(t)
	// Install on a populated native schema; ordinary issuance is already usable.
	unlimited, err := apikeypg.NewService(f.pool, f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := unlimited.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	metadataIssue(t, f, unlimited, f.caller, "pre-quota")
	installQuota(t, f)
	c := quotaConfiguration(t, f.config, apikey.TokenBucketPolicy{Capacity: 2, RefillAmount: 1, RefillInterval: time.Hour})
	s, record, r := quotaKey(t, f, c)
	original, err := s.VerifyAndConsume(f.ctx, r)
	if err != nil || original.Validate() != nil || original.State != apikey.VerificationAttemptDebited || original.Result == nil || original.Quota == nil || original.Quota.Remaining != 1 {
		t.Fatal("real finite key did not debit exactly one token", err)
	}
	wrong := r
	wrong.Secret, _ = apikey.GenerateSecret()
	if out, err := s.VerifyAndConsume(f.ctx, wrong); err == nil || out.Result != nil || out.Quota != nil {
		t.Fatal("changed original secret did not conflict before debit")
	}
	changedDebit := r
	changedDebit.DebitAmount = 2
	if out, err := s.VerifyAndConsume(f.ctx, changedDebit); err == nil || out.Result != nil || out.Quota != nil || out.State == apikey.VerificationAttemptDebited {
		t.Fatal("changed debit reused original quota effect", err)
	}
	changed := c
	spec := changed.Configuration.Spec()
	spec.TokenBucket.RefillAmount++
	changed.Configuration, err = apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal(err)
	}
	different, err := apikeypg.NewService(f.pool, changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := different.CheckConfiguration(f.ctx, baselineTenant); err == nil {
		t.Fatal("changed immutable policy reused installed configuration identity")
	}
	if out, err := different.VerifyAndConsume(f.ctx, r); err == nil || out.Result != nil || out.Quota != nil {
		t.Fatal("changed quota settings recovered original debit", err)
	}
	for i := 0; i < 2; i++ {
		replay, err := s.VerifyAndConsume(f.ctx, r)
		if err != nil || replay.Validate() != nil || replay.State != apikey.VerificationAttemptDebited || replay.Quota == nil || *replay.Quota != *original.Quota || replay.Result == nil || replay.Result.ValidUntil != original.Result.ValidUntil {
			t.Fatal("replay debited/refilled or renewed original observation", err)
		}
		q := apikey.VerificationReconcileQuery{AttemptID: r.AttemptID, TenantID: r.TenantID, Fingerprint: original.Fingerprint, Original: original.Original}
		history, err := s.ReconcileVerifyAndConsume(f.ctx, q)
		if err != nil || history.Validate() != nil || history.Quota == nil || *history.Quota != *original.Quota || history.Result == nil || history.Result.ValidUntil != original.Result.ValidUntil {
			t.Fatal("status inquiry changed original quota or authority", err)
		}
	}
	r.AttemptID = apikey.VerificationAttemptID(commandID(t))
	second, err := s.VerifyAndConsume(f.ctx, r)
	if err != nil || second.Quota == nil || second.Quota.Remaining != 0 {
		t.Fatal("second original attempt did not exhaust allowance", err)
	}
	r.AttemptID = apikey.VerificationAttemptID(commandID(t))
	denied, err := s.VerifyAndConsume(f.ctx, r)
	if !errors.Is(err, apikey.ErrDenied) || denied.Validate() != nil || denied.State != apikey.VerificationAttemptNotDebited || denied.Result != nil || denied.Quota == nil || denied.Quota.Remaining != 0 {
		t.Fatal("exhausted key acquired authority or lost known non-debit", err)
	}
	assertStoredKeyState(t, f.ctx, f.pool, r.TenantID, record.ID, apikey.KeyActive, record.Version, record.AuthorityVersion)
}

func TestNativeQuotaConcurrentAttemptsAndContinuousRefill(t *testing.T) {
	f := setupNativeConsumer(t)
	installQuota(t, f)
	c := quotaConfiguration(t, f.config, apikey.TokenBucketPolicy{Capacity: 2, RefillAmount: 1, RefillInterval: time.Hour})
	s, _, r := quotaKey(t, f, c)
	requests := make([]apikey.AtomicVerificationRequest, 6)
	for i := range requests {
		requests[i] = r
		requests[i].AttemptID = apikey.VerificationAttemptID(commandID(t))
	}
	type answer struct {
		out apikey.AtomicVerificationResult
		err error
	}
	answers := make(chan answer, len(requests))
	var group sync.WaitGroup
	for _, request := range requests {
		group.Go(func() { out, err := s.VerifyAndConsume(f.ctx, request); answers <- answer{out, err} })
	}
	group.Wait()
	close(answers)
	debited := 0
	for a := range answers {
		if a.out.Validate() != nil {
			t.Fatal("concurrent quota result invalid")
		}
		if a.out.State == apikey.VerificationAttemptDebited && a.err == nil {
			debited++
		} else if !errors.Is(a.err, apikey.ErrDenied) || a.out.State != apikey.VerificationAttemptNotDebited || a.out.Quota == nil {
			t.Fatal("concurrent quota outcome not attributable", a.err)
		}
	}
	if debited != 2 {
		t.Fatal("concurrent attempts exceeded or lost capacity", debited)
	}
	// A separate configured bucket proves real DB-time refill, not a clock stub.
	c = quotaConfiguration(t, f.config, apikey.TokenBucketPolicy{Capacity: 1, RefillAmount: 1, RefillInterval: 500 * time.Millisecond})
	spec := c.Configuration.Spec()
	spec.ID = "automation"
	c.Configuration, _ = apikey.NewConfiguration(spec)
	fast, _, next := quotaKey(t, f, c)
	first, err := fast.VerifyAndConsume(f.ctx, next)
	if err != nil || first.Quota == nil {
		t.Fatal("fast quota initial debit", err)
	}
	timer := time.NewTimer(600 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.ctx.Done():
		t.Fatal("refill canceled")
	}
	next.AttemptID = apikey.VerificationAttemptID(commandID(t))
	refilled, err := fast.VerifyAndConsume(f.ctx, next)
	if err != nil || refilled.State != apikey.VerificationAttemptDebited || refilled.Quota == nil || !refilled.Quota.ObservedAt.After(first.Quota.ObservedAt) {
		t.Fatal("database time did not refill bounded allowance", err)
	}
}

func TestNativeQuotaLostCommitRetainsExactDebit(t *testing.T) {
	f := setupNativeConsumer(t)
	installQuota(t, f)
	c := quotaConfiguration(t, f.config, apikey.TokenBucketPolicy{Capacity: 2, RefillAmount: 1, RefillInterval: time.Hour})
	s, _, request := quotaKey(t, f, c)
	fault := &legacyCommitFault{marker: []byte("INSERT INTO identity_api_keys.quotas")}
	faulted, err := database.Connect(f.ctx, database.Config{DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
		c.ConnConfig.DialFunc = fault.dial
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if faulted.Close(ctx) != nil {
			t.Error("quota fault pool cleanup")
		}
	})
	faultService, err := apikeypg.NewService(faulted, c)
	if err != nil {
		t.Fatal(err)
	}
	out, err := faultService.VerifyAndConsume(f.ctx, request)
	var unknown apikey.ErrDebitOutcomeUnknown
	if !fault.hit.Load() || !errors.As(err, &unknown) || unknown.AttemptID != request.AttemptID || out.Validate() != nil || out.State != apikey.VerificationAttemptPossibleDebit || out.Result != nil || out.Quota != nil {
		t.Fatal("actual lost quota COMMIT did not preserve possible-debit/no principal", err)
	}
	query := apikey.VerificationReconcileQuery{AttemptID: request.AttemptID, TenantID: request.TenantID, Fingerprint: out.Fingerprint, Original: out.Original}
	deadline := time.Now().Add(8 * time.Second)
	for {
		known, err := s.ReconcileVerifyAndConsume(f.ctx, query)
		if err == nil && known.State == apikey.VerificationAttemptDebited {
			if known.Quota == nil || known.Quota.Remaining != 1 {
				t.Fatal("reconciliation lost original debit")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("original quota debit did not reconcile", err)
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-f.ctx.Done():
			t.Fatal("quota recovery canceled")
		}
	}
	for i := 0; i < 2; i++ {
		replay, err := s.VerifyAndConsume(f.ctx, request)
		if err != nil || replay.Quota == nil || replay.Quota.Remaining != 1 {
			t.Fatal("original debit repeated after commit loss", err)
		}
	}
}

func TestNativeQuotaDenialAndRequiredAuditRollbackDoNotDebit(t *testing.T) {
	f := setupNativeConsumer(t)
	installQuota(t, f)
	c := quotaConfiguration(t, f.config, apikey.TokenBucketPolicy{Capacity: 2, RefillAmount: 1, RefillInterval: time.Hour})
	s, record, request := quotaKey(t, f, c)
	assertEmpty := func() {
		t.Helper()
		var count int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity_api_keys.quotas WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3`, baselineTenant, request.ConfigurationID, string(record.ID)).Scan(&count); err != nil || count != 0 {
			t.Fatal("denied/rolled-back authentication changed quota state", err)
		}
	}
	wrong := request
	wrong.AttemptID = apikey.VerificationAttemptID(commandID(t))
	wrong.Secret, _ = apikey.GenerateSecret()
	if out, err := s.VerifyAndConsume(f.ctx, wrong); !errors.Is(err, apikey.ErrDenied) || out.Validate() != nil || out.State != apikey.VerificationAttemptNotDebited || out.Quota != nil {
		t.Fatal("wrong secret acquired quota outcome", err)
	}
	assertEmpty()
	// Fail success persistence after the quota write, but leave the real owner's
	// separate terminal failure-audit transaction available to prove rollback.
	// Blocking that audit too correctly leaves coordinator recovery Unknown.
	_, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.reject_quota_auth_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='identity.api_key.authenticate' AND NEW.outcome=1 THEN RAISE EXCEPTION 'injected required audit outage'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_quota_auth_audit BEFORE INSERT ON audit.records FOR EACH ROW EXECUTE FUNCTION public.reject_quota_auth_audit()`)
	if err != nil {
		t.Fatal("quota audit fault setup", err)
	}
	failed, verifyErr := s.VerifyAndConsume(f.ctx, request)
	_, dropErr := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER reject_quota_auth_audit ON audit.records; DROP FUNCTION public.reject_quota_auth_audit()`)
	if dropErr != nil {
		t.Fatal("quota audit fault cleanup", dropErr)
	}
	if verifyErr == nil || failed.Validate() != nil || failed.State != apikey.VerificationAttemptNotDebited || failed.Result != nil || failed.Quota != nil || failed.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("required audit rollback lost known non-debit", verifyErr)
	}
	assertEmpty()
	// Current permission withdrawal can narrow the stored grant, but a denied
	// write permission must not charge the key for authentication it did not get.
	f.deniedGrant.Store(true)
	advanceUserPolicy(t, f.ctx, f.pool, c.Profile.PolicyNamespace, f.user)
	denied := request
	denied.AttemptID = apikey.VerificationAttemptID(commandID(t))
	denied.RequiredPermissions = []string{"invoice.write"}
	if out, err := s.VerifyAndConsume(f.ctx, denied); !errors.Is(err, apikey.ErrDenied) || out.State != apikey.VerificationAttemptNotDebited || out.Quota != nil || out.Result != nil {
		t.Fatal("withdrawn permission consumed quota", err)
	}
	assertEmpty()
	request.AttemptID = apikey.VerificationAttemptID(commandID(t))
	read, err := s.VerifyAndConsume(f.ctx, request)
	if err != nil || read.State != apikey.VerificationAttemptDebited || read.Quota == nil || read.Quota.Remaining != 1 {
		t.Fatal("denial or rollback spent allowance", err)
	}
}

func TestNativeQuotaOrganizationOwnerIsIndependentOfCreator(t *testing.T) {
	f := setupNativeConsumer(t)
	installOrganizationKeyOwners(t, f)
	installQuota(t, f)
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	org, repository, c := organizationKeyOwners(t, f, organization.ID(id))
	c = quotaConfiguration(t, c, apikey.TokenBucketPolicy{Capacity: 2, RefillAmount: 1, RefillInterval: time.Hour})
	created, err := org.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: organization.Authentication{TenantID: f.caller.TenantID, Bearer: f.caller.Bearer}, CommandID: commandID(t), ID: organization.ID(id), Slug: "quota-owner", Name: "Quota owner", CorrelationID: "quota-create-owner"}, "192.0.2.20")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := org.Execute(f.ctx, created); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real quota organization creation", err)
	}
	second, secondID := f.register()
	add, err := org.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: organization.Authentication{TenantID: f.caller.TenantID, Bearer: f.caller.Bearer}, CommandID: commandID(t), OrganizationID: organization.ID(id), UserID: secondID, Role: organization.RoleOwner, OrganizationVersion: 1, CorrelationID: "quota-add-owner"}, "192.0.2.20")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := org.Execute(f.ctx, add); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real quota owner admission", err)
	}
	s, err := apikeypg.NewOrganizationService(f.pool, c, repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	key, _ := identity.NewIdempotencyKey([]byte("quota-organization-key"))
	issued, err := s.CreateOrganization(f.ctx, apikey.OrganizationCreateRequest{CreateRequest: apikey.CreateRequest{Authentication: f.caller, IdempotencyKey: key, Name: "organization quota", Permissions: []string{"invoice.read"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.21"}, OrganizationID: apikey.OrganizationID(id)})
	if err != nil {
		t.Fatal("real organization quota issuance", err)
	}
	record, ok := issued.Record()
	if !ok {
		t.Fatal("organization key record absent")
	}
	wire, err := issued.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := apikey.ParseSecret(wire)
	if err != nil {
		t.Fatal(err)
	}
	remove, err := org.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: organization.Authentication{TenantID: second.TenantID, Bearer: second.Bearer}, CommandID: commandID(t), OrganizationID: organization.ID(id), UserID: f.user, OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "quota-remove-creator"}, "192.0.2.22")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := org.Execute(f.ctx, remove); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real quota creator removal", err)
	}
	request := apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: c.Configuration.Spec().ID, ConfigurationRevision: c.Configuration.Spec().Revision, Candidate: record.ID, Secret: secret, RequiredPermissions: []string{"invoice.read"}, DebitAmount: 1}
	out, err := s.VerifyAndConsume(f.ctx, request)
	if err != nil || out.Validate() != nil || out.State != apikey.VerificationAttemptDebited || out.Quota == nil || out.Quota.Remaining != 1 || out.Result == nil || out.Result.Owner.Spec().Kind != apikey.OwnerOrganization || out.Result.Owner.Spec().UserID != "" {
		t.Fatal("finite quota turned organization key into creator authority", err)
	}
}

func TestNativeQuotaWithdrawnAuthorityCannotEraseOriginalDebit(t *testing.T) {
	for _, withdrawal := range []string{"tenant", "user", "configuration"} {
		t.Run(withdrawal, func(t *testing.T) {
			f := setupNativeConsumer(t)
			installQuota(t, f)
			c := quotaConfiguration(t, f.config, apikey.TokenBucketPolicy{Capacity: 2, RefillAmount: 1, RefillInterval: time.Hour})
			s, record, request := quotaKey(t, f, c)
			original, err := s.VerifyAndConsume(f.ctx, request)
			if err != nil || original.State != apikey.VerificationAttemptDebited || original.Quota == nil {
				t.Fatal("withdrawal original debit precondition", err)
			}
			// Infrastructure probes withdraw only already-genuine authority. They
			// neither seed positive authority nor claim the admin/cascade journey.
			var changed int64
			switch withdrawal {
			case "tenant":
				tag, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.tenant_authorities SET enabled=false,version=version+1 WHERE tenant_id=$1 AND enabled`, baselineTenant)
				if err != nil {
					t.Fatal(err)
				}
				changed = tag.RowsAffected()
			case "user":
				tag, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.users SET status='suspended',version=version+1,authority_version=authority_version+1 WHERE tenant_id=$1 AND user_id=$2 AND status='active'`, baselineTenant, string(f.user))
				if err != nil {
					t.Fatal(err)
				}
				changed = tag.RowsAffected()
			case "configuration":
				tag, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_api_keys.configurations SET enabled=false,authority_version=authority_version+1 WHERE tenant_id=$1 AND configuration_id=$2 AND enabled`, baselineTenant, request.ConfigurationID)
				if err != nil {
					t.Fatal(err)
				}
				changed = tag.RowsAffected()
			}
			if changed != 1 {
				t.Fatal("authority withdrawal did not address one real owner")
			}
			assertUndisclosed := func(out apikey.AtomicVerificationResult, err error) {
				t.Helper()
				var unknown apikey.ErrDebitOutcomeUnknown
				if !errors.As(err, &unknown) || unknown.AttemptID != out.AttemptID || out.Validate() != nil || out.State != apikey.VerificationAttemptPossibleDebit || out.Outcome != identity.CommitOutcomeUnknown || out.Result != nil || out.Quota != nil {
					t.Fatal("withdrawn authority disclosed principal or falsely asserted original non-debit", err)
				}
			}
			assertUndisclosed(s.VerifyAndConsume(f.ctx, request))
			q := apikey.VerificationReconcileQuery{AttemptID: request.AttemptID, TenantID: request.TenantID, Fingerprint: original.Fingerprint, Original: original.Original}
			assertUndisclosed(s.ReconcileVerifyAndConsume(f.ctx, q))
			fresh := request
			fresh.AttemptID = apikey.VerificationAttemptID(commandID(t))
			// Lack of query authority must not disclose whether an original ID
			// exists. An unseen caller-selected ID has the same uncertain shape.
			assertUndisclosed(s.VerifyAndConsume(f.ctx, fresh))
			var balance string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT balance::text FROM identity_api_keys.quotas WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3`, baselineTenant, request.ConfigurationID, string(record.ID)).Scan(&balance); err != nil || balance != "3600000000" {
				t.Fatal("withdrawal/retry changed original bucket", err)
			}
		})
	}
}
