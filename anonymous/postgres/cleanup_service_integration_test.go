//go:build integration

package anonymouspostgres_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	anonymouspg "github.com/faustbrian/go-identity/anonymous/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
)

// C01/C06: exercise the supported maintenance service, not a test-written
// participant. Genuine guest issuance precedes historical fixture aging; no
// expired bearer, caller-selected clock or fabricated authentication is used.
func TestNativeAbandonedGuestCleanupUsesBoundedPrimarySelection(t *testing.T) {
	f := newPublicAnonymousFixture(t)
	installCleanupHistory(t, f)
	var guests []identity.UserID
	var tenant identity.TenantID
	for n := range 3 {
		issued, err := f.service.Signin(f.ctx, f.fresh())
		if err != nil {
			t.Fatal("genuine guest prerequisite", err)
		}
		s, _ := issued.Session.Session.Bindings()
		tenant = s.TenantID
		guests = append(guests, s.UserID)
		if n < 2 {
			agePrunedCleanupGuest(t, f, tenant, s.UserID, int64(52-n*4))
		}
	}
	service, err := anonymouspg.NewCleanupService(f.pool, cleanupServiceConfig(t, f), f.keys)
	if err != nil {
		t.Fatal("public cleanup composition", err)
	}
	run, _ := identity.NewCommandID()
	result, err := service.CleanupExpired(f.ctx, anonymouspg.CleanupRequest{TenantID: tenant, RunID: run, Limit: 1})
	if err != nil || len(result.Items) != 1 || result.Items[0].UserID != guests[0] || result.Items[0].Outcome != identity.CommitOutcomeCommitted || result.Items[0].Recovery.CommandID == "" || !result.LagKnown || result.RemainingLag <= 0 || result.ObservedAt.IsZero() || result.Next == nil {
		t.Fatal("bounded oldest expired guest did not complete", err, len(result.Items), result.RemainingLag)
	}
	for n, user := range guests {
		var state int16
		var status string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT a.state,u.status FROM anonymous_store.subjects a JOIN identity.users u USING(tenant_id,user_id) WHERE tenant_id=$1 AND user_id=$2`, string(tenant), string(user)).Scan(&state, &status); err != nil {
			t.Fatal(err)
		}
		if n == 0 && (state != int16(anonymous.StateAnonymized) || status != "anonymized") || n > 0 && (state != int16(anonymous.StateActive) || status != "active") {
			t.Fatal("cleanup exceeded its batch or missed terminalization", n, state, status)
		}
	}
	// Original replay must retain its command, even after the lifecycle is
	// terminal and every original session payload has already been pruned.
	replay, err := service.CleanupSubject(f.ctx, anonymouspg.CleanupSubjectRequest{TenantID: tenant, UserID: guests[0], RunID: run})
	if err != nil || !replay.Replayed || replay.Outcome != identity.CommitOutcomeCommitted || replay.Recovery != result.Items[0].Recovery {
		t.Fatal("cleanup retry created another transition", err, replay.Outcome)
	}
	recovered, err := service.RecoverCleanup(f.ctx, replay.Recovery)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Recovery != replay.Recovery {
		t.Fatal("original service-owned command was not recoverable", err)
	}
	var effects, audits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM anonymous_store.disposals WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$3 AND r.outcome=$4),(SELECT count(*) FROM public.outbox_messages WHERE topic='anonymous.expired.v1')`, string(tenant), string(guests[0]), mustExpiryCommandBytes(t, replay.Recovery.CommandID), int64(audit.OutcomeSucceeded)).Scan(&effects, &audits, &events); err != nil || effects != 1 || audits != 1 || events != 1 {
		t.Fatal("cleanup lost or duplicated required effects", err, effects, audits, events)
	}
}

func TestNativeCleanupPreservesStoredDisposalPolicies(t *testing.T) {
	for _, policy := range []anonymous.CleanupPolicy{anonymous.CleanupDelete, anonymous.CleanupRetain} {
		t.Run(fmt.Sprintf("policy=%d", policy), func(t *testing.T) {
			f := newPublicAnonymousFixture(t)
			installCleanupHistory(t, f)
			config := f.config
			selected, _ := config.Policy.Config()
			selected.Cleanup = policy
			config.Policy, _ = anonymous.NewPolicy(selected)
			var err error
			f.service, err = anonymouspg.NewSigninService(f.pool, config, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			tenant, user := cleanupGuest(t, f, 48)
			var originalAttributes, originalProfiles int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.user_attributes WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.user_profiles WHERE tenant_id=$1 AND user_id=$2)`, string(tenant), string(user)).Scan(&originalAttributes, &originalProfiles); err != nil || originalAttributes == 0 {
				t.Fatal("retained guest payload prerequisite", err)
			}
			service, err := anonymouspg.NewCleanupService(f.pool, cleanupServiceConfig(t, f), f.keys)
			if err != nil {
				t.Fatal(err)
			}
			run, _ := identity.NewCommandID()
			out, err := service.CleanupSubject(f.ctx, anonymouspg.CleanupSubjectRequest{TenantID: tenant, UserID: user, RunID: run})
			if err != nil || out.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("stored policy cleanup failed", err)
			}
			var state int16
			var status string
			var attributes, profiles int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT a.state,u.status,(SELECT count(*) FROM identity.user_attributes WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.user_profiles WHERE tenant_id=$1 AND user_id=$2) FROM anonymous_store.subjects a JOIN identity.users u USING(tenant_id,user_id) WHERE tenant_id=$1 AND user_id=$2`, string(tenant), string(user)).Scan(&state, &status, &attributes, &profiles); err != nil {
				t.Fatal(err)
			}
			if policy == anonymous.CleanupDelete && (state != int16(anonymous.StateExpired) || status != "deleted" || attributes != 0 || profiles != 0) || policy == anonymous.CleanupRetain && (state != int16(anonymous.StateRetained) || status != "deleted" || attributes != originalAttributes || profiles != originalProfiles) {
				t.Fatal("maintenance replaced the stored disposal policy", state, status, attributes, profiles)
			}
		})
	}
}

func installCleanupHistory(t *testing.T, f publicAnonymousFixture, selectedUpgrade ...bool) {
	t.Helper()
	var base migrations.Source = kernel.AnonymousDisposalMigrationSource{Base: kernel.DirectoryAuthorityMigrationSource{Base: kernel.AnonymousIdentityMigrationSource{Base: kernel.IdentifierNormalizationMigrationSource{Base: kernel.IdentifierMutationMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}, Version: 14}, Version: 15, GlobalAuthorityID: "anonymous-deployment", TenantIDs: []identity.TenantID{"tenant-a", "AAAAAAAAAAAAAAAAAAAAAQ"}}, Version: 16}
	upgrade := len(selectedUpgrade) == 1 && selectedUpgrade[0]
	version := migrations.Version(62)
	if upgrade {
		base = kernel.AnonymousUpgradeDisposalMigrationSource{Base: base, Version: 70}
		version = 80
	}
	for _, source := range []migrations.Source{kernel.AnonymousExpiryDisposalMigrationSource{Base: base, Version: version}, sessionpg.AnonymousExpiryMigrationSource{Schema: "session_store", Version: version + 1, Upgrade: upgrade}, anonymouspg.ExpiryMigrationSource{Schema: "anonymous_store", Version: version + 2}} {
		history, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range history {
			if step.Version() >= version {
				if _, err := f.pool.Raw().Exec(f.ctx, step.UpSQL()); err != nil {
					t.Fatal("forward cleanup history", err)
				}
			}
		}
	}
}

// C04/C07: both orders use genuine upgrade commands and protected target proof.
// Aging only advances the historical guest lifecycle across expiry; it does not
// manufacture an upgrade or maintenance authority. No permanent target is erased.
func TestNativeCleanupFencesActualPermanentUpgrade(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(fmt.Sprintf("upgrade-completed=%t", completed), func(t *testing.T) {
			var j nativeUpgradeJourney
			var cleanup *anonymouspg.CleanupService
			var cleaned anonymouspg.CleanupItem
			hook := func(ctx context.Context, in identity.RetentionPolicyInput) error {
				agePrunedCleanupGuest(t, j.f, in.TenantID, in.SubjectID, 48)
				run, _ := identity.NewCommandID()
				var err error
				cleaned, err = cleanup.CleanupSubject(ctx, anonymouspg.CleanupSubjectRequest{TenantID: in.TenantID, UserID: in.SubjectID, RunID: run})
				return err
			}
			if completed {
				j = newNativeUpgradeJourney(t)
			} else {
				j = newNativeUpgradeJourney(t, hook)
			}
			if completed {
				out, err := j.service.Upgrade(j.f.ctx, j.request)
				if err != nil || out.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("genuine completed upgrade prerequisite", err)
				}
				// The expiry suffix must preserve already-populated upgrade history.
				installCleanupHistory(t, j.f, true)
			} else {
				installCleanupHistory(t, j.f, true)
			}
			var err error
			cleanup, err = anonymouspg.NewCleanupService(j.f.pool, cleanupServiceConfig(t, j.f), j.f.keys)
			if err != nil {
				t.Fatal(err)
			}
			guest, _ := j.guest.Bindings()
			if completed {
				agePrunedCleanupGuest(t, j.f, guest.TenantID, guest.UserID, 48)
				run, _ := identity.NewCommandID()
				out, err := cleanup.CleanupExpired(j.f.ctx, anonymouspg.CleanupRequest{TenantID: guest.TenantID, RunID: run, Limit: 1})
				if err != nil || len(out.Items) != 0 || !out.LagKnown || out.RemainingLag != 0 {
					t.Fatal("upgraded guest entered expired selection", err)
				}
				if item, err := cleanup.CleanupSubject(j.f.ctx, anonymouspg.CleanupSubjectRequest{TenantID: guest.TenantID, UserID: guest.UserID, RunID: run}); err == nil || item.Recovery.CommandID != "" {
					t.Fatal("direct maintenance reentered upgraded lifecycle", err)
				}
			} else {
				out, err := j.service.Upgrade(j.f.ctx, j.request)
				if cleaned.Outcome != identity.CommitOutcomeCommitted || err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Session.Token != (session.Token{}) {
					t.Fatal("admitted upgrade survived actual intervening cleanup", err, cleaned.Outcome, out.Outcome)
				}
			}
			var targetStatus string
			var targetDisposals, consumed int
			if err := j.f.pool.Raw().QueryRow(j.f.ctx, `SELECT status,(SELECT count(*) FROM identity.anonymous_disposals WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity_password.reauthentication_records WHERE tenant_id=$1 AND user_id=$2 AND consumed_command_id IS NOT NULL) FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(guest.TenantID), string(upgradeTargetID)).Scan(&targetStatus, &targetDisposals, &consumed); err != nil || targetStatus != "active" || targetDisposals != 0 || completed && consumed != 1 || !completed && consumed != 0 {
				t.Fatal("cleanup erased target or partially consumed upgrade proof", err, targetStatus, targetDisposals, consumed)
			}
		})
	}
}

func agePrunedCleanupGuest(t *testing.T, f publicAnonymousFixture, tenant identity.TenantID, user identity.UserID, hours int64) {
	t.Helper()
	for _, sql := range []string{
		`DELETE FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2`,
		`UPDATE session_store.families SET state='revoked',issued_at=to_char((issued_at::timestamptz-$3::bigint*interval '1 hour') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US')||'000Z' WHERE tenant_id=$1 AND user_id=$2`,
		`UPDATE anonymous_store.subjects SET created_at=created_at-$3::bigint*interval '1 hour',expires_at=expires_at-$3::bigint*interval '1 hour' WHERE tenant_id=$1 AND user_id=$2`,
	} {
		args := []any{string(tenant), string(user)}
		if sql[0] != 'D' {
			args = append(args, hours)
		}
		if _, err := f.pool.Raw().Exec(f.ctx, sql, args...); err != nil {
			t.Fatal("historical expired/pruned fixture", err)
		}
	}
}

func cleanupServiceConfig(t *testing.T, f publicAnonymousFixture, hooks ...func(context.Context, identity.RetentionPolicyInput) error) anonymouspg.CleanupConfig {
	t.Helper()
	denyRisk := func(context.Context, identity.RiskPolicyInput) (identity.RiskPolicyDecision, error) {
		return identity.RiskPolicyDecision{}, identity.ForbiddenError{}
	}
	retention, err := identity.NewPolicyEvaluator(identity.PolicySet{Authorize: anonymousPolicy{}, AssessRisk: denyRisk,
		MapClaims: func(context.Context, identity.ClaimsPolicyInput) (identity.ClaimsPolicyDecision, error) {
			return identity.ClaimsPolicyDecision{}, identity.ForbiddenError{}
		},
		Redact: func(context.Context, identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
			return identity.RedactionPolicyDecision{}, identity.ForbiddenError{}
		},
		DecideRetention: func(_ context.Context, in identity.RetentionPolicyInput) (identity.RetentionPolicyDecision, error) {
			if in.ActorID != "guest-maintenance" || in.OperationID != "identity.anonymous.expire" || in.Resource.Kind != "anonymous" || in.Resource.ID != string(in.SubjectID) {
				return identity.RetentionPolicyDecision{}, identity.ForbiddenError{}
			}
			for _, hook := range hooks {
				if err := hook(f.ctx, in); err != nil {
					return identity.RetentionPolicyDecision{}, err
				}
			}
			d := identity.RetentionAllow
			if in.LegalHold {
				d = identity.RetentionBlockLegalHold
			}
			return identity.RetentionPolicyDecision{Disposition: d, PolicyID: "guest-retention", PolicyVersion: 1, Reasons: []identity.PolicyReason{"expired"}}, nil
		},
	}, identity.PolicyEvaluatorConfig{PolicyID: "guest-retention", PolicyVersion: 1, Reasons: []identity.PolicyReason{"expired"}, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return anonymouspg.CleanupConfig{Repository: f.config.Repository, Sessions: f.config.Sessions, GlobalAuthorityID: f.config.Profile.GlobalAuthorityID,
		ActorID: "guest-maintenance", PolicyID: "guest-maintenance", ConfigurationID: "guest-cleanup-v1", MaximumBatch: 2, Clock: clock.System{},
		Retention: retention, RetentionPolicyVersion: 1, RequestKeys: f.config.RequestKeys, Coordinator: f.config.Coordinator,
		IntentKey: [32]byte{74}, ActiveEnvelopeKeyID: f.config.ActiveEnvelopeKeyID}
}

type cleanupPolicyFunc func(context.Context, authorization.DecisionContext) (authorization.Decision, error)

func (f cleanupPolicyFunc) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	return f(ctx, c)
}

func cleanupGuest(t *testing.T, f publicAnonymousFixture, hours int64) (identity.TenantID, identity.UserID) {
	t.Helper()
	issued, err := f.service.Signin(f.ctx, f.fresh())
	if err != nil {
		t.Fatal("genuine cleanup guest", err)
	}
	s, _ := issued.Session.Session.Bindings()
	agePrunedCleanupGuest(t, f, s.TenantID, s.UserID, hours)
	return s.TenantID, s.UserID
}

// C02/C03/C06: denied service policy never selects; held rows stay observable
// while an explicit seek cursor lets a later eligible guest make progress.
func TestNativeCleanupCurrentPolicyHoldsAndCursor(t *testing.T) {
	f := newPublicAnonymousFixture(t)
	installCleanupHistory(t, f)
	tenant, held := cleanupGuest(t, f, 52)
	_, later := cleanupGuest(t, f, 48)
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.users SET legal_hold=true,legal_hold_version=legal_hold_version+1 WHERE tenant_id=$1 AND user_id=$2`, string(tenant), string(held)); err != nil {
		t.Fatal(err)
	}
	var deny, unavailable atomic.Bool
	c := cleanupServiceConfig(t, f, func(context.Context, identity.RetentionPolicyInput) error {
		if unavailable.Load() {
			return identity.UnavailableError{}
		}
		return nil
	})
	policy := cleanupPolicyFunc(func(_ context.Context, request authorization.DecisionContext) (authorization.Decision, error) {
		outcome := authorization.Allow
		if deny.Load() {
			outcome = authorization.Deny
		}
		return authorization.Decision{Outcome: outcome, Revision: request.PolicyRevision}, nil
	})
	a, q := *c.Coordinator.AdmissionPolicy, *c.Coordinator.QueryPolicy
	a.Authorization, q.Authorization = policy, policy
	c.Coordinator.AdmissionPolicy, c.Coordinator.QueryPolicy = &a, &q
	c.RequestKeys.Policy.Authorization = policy
	service, err := anonymouspg.NewCleanupService(f.pool, c, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	run, _ := identity.NewCommandID()
	request := anonymouspg.CleanupRequest{TenantID: tenant, RunID: run, Limit: 1}
	for _, invalid := range []anonymouspg.CleanupSubjectRequest{
		{TenantID: "", UserID: held, RunID: run},
		{TenantID: tenant, UserID: "invalid", RunID: run},
		{TenantID: tenant, UserID: held, RunID: "invalid"},
	} {
		if out, err := service.CleanupSubject(f.ctx, invalid); !errors.Is(err, anonymous.ErrInvalidInput) || out.Recovery.CommandID != "" || out.Outcome != identity.CommitOutcomeInvalid {
			t.Errorf("malformed subject request lost invalid-input classification: %v", err)
		}
	}
	for _, limit := range []uint32{0, c.MaximumBatch + 1} {
		invalid := request
		invalid.Limit = limit
		if out, err := service.CleanupExpired(f.ctx, invalid); err == nil || len(out.Items) != 0 || out.LagKnown {
			t.Fatal("invalid batch bound reached selection", limit, err)
		}
	}
	canceled, stop := context.WithCancel(f.ctx)
	stop()
	if out, err := service.CleanupExpired(canceled, request); !errors.Is(err, context.Canceled) || len(out.Items) != 0 || out.LagKnown {
		t.Fatal("canceled maintenance reached selection", err)
	}
	deny.Store(true)
	if out, err := service.CleanupExpired(f.ctx, request); err == nil || len(out.Items) != 0 || out.LagKnown {
		t.Fatal("denied service exposed or changed cleanup", err)
	}
	deny.Store(false)
	unavailable.Store(true)
	if out, err := service.CleanupExpired(f.ctx, request); err == nil || len(out.Items) != 1 || out.Items[0].Recovery.CommandID != "" || out.LagKnown {
		t.Fatal("unavailable retention was skipped as ordinary deferral", err)
	}
	unavailable.Store(false)
	out, err := service.CleanupExpired(f.ctx, request)
	if err != nil || len(out.Items) != 1 || out.Items[0].UserID != held || out.Items[0].Error == nil || out.Items[0].Outcome == identity.CommitOutcomeCommitted || out.Next == nil || !out.LagKnown || out.RemainingLag <= 0 {
		t.Fatal("hold was erased or backlog hidden", err)
	}
	request.After = out.Next
	out, err = service.CleanupExpired(f.ctx, request)
	if err != nil || len(out.Items) != 1 || out.Items[0].UserID != later || out.Items[0].Outcome != identity.CommitOutcomeCommitted || !out.LagKnown || out.RemainingLag <= 0 {
		t.Fatal("held first page starved later cleanup or vanished from lag", err)
	}
	deny.Store(true)
	if recovered, err := service.RecoverCleanup(f.ctx, out.Items[0].Recovery); err == nil || recovered.Recovery.CommandID != "" || recovered.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("withdrawn service policy revealed retained outcome", err)
	}
	deny.Store(false)
	foreign := out.Items[0].Recovery
	foreign.ActorID = "another-maintainer"
	if recovered, err := service.RecoverCleanup(f.ctx, foreign); err == nil || recovered.Recovery.CommandID != "" {
		t.Fatal("another service recovered original scope", err)
	}
	var state int16
	var status string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT a.state,u.status FROM anonymous_store.subjects a JOIN identity.users u USING(tenant_id,user_id) WHERE tenant_id=$1 AND user_id=$2`, string(tenant), string(held)).Scan(&state, &status); err != nil || state != 1 || status != "active" {
		t.Fatal("legal-hold payload was terminalized", err)
	}
}

// C04/C05: an actual post-admission hold change and a reached required outbox
// failure both roll back every provisional owner, audit and lifecycle effect.
func TestNativeCleanupFencesHoldRaceAndRequiredOutbox(t *testing.T) {
	for _, mode := range []string{"hold-race", "directory", "original-deadline", "outbox"} {
		t.Run(mode, func(t *testing.T) {
			f := newPublicAnonymousFixture(t)
			installCleanupHistory(t, f)
			tenant, user := cleanupGuest(t, f, 48)
			observedClock := &cleanupObservedClock{}
			var hooks []func(context.Context, identity.RetentionPolicyInput) error
			if mode != "outbox" {
				hooks = append(hooks, func(ctx context.Context, in identity.RetentionPolicyInput) error {
					if mode == "original-deadline" {
						observedClock.offset.Store(int64(21 * time.Second))
						return nil
					}
					if mode == "directory" {
						_, err := f.pool.Raw().Exec(ctx, `UPDATE identity.tenant_authorities SET enabled=false,version=version+1 WHERE tenant_id=$1`, string(in.TenantID))
						return err
					}
					_, err := f.pool.Raw().Exec(ctx, `UPDATE identity.users SET legal_hold=true,legal_hold_version=legal_hold_version+1 WHERE tenant_id=$1 AND user_id=$2`, string(in.TenantID), string(in.SubjectID))
					return err
				})
			} else {
				if _, err := f.pool.Raw().Exec(f.ctx, `CREATE SEQUENCE public.cleanup_outbox_reached; CREATE FUNCTION public.reject_cleanup_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('public.cleanup_outbox_reached'); RAISE EXCEPTION 'owned cleanup outbox failure'; END $$; CREATE TRIGGER reject_cleanup_outbox BEFORE INSERT ON public.outbox_messages FOR EACH ROW WHEN(NEW.topic='anonymous.expired.v1') EXECUTE FUNCTION public.reject_cleanup_outbox()`); err != nil {
					t.Fatal(err)
				}
			}
			config := cleanupServiceConfig(t, f, hooks...)
			config.Clock = observedClock
			service, err := anonymouspg.NewCleanupService(f.pool, config, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			run, _ := identity.NewCommandID()
			out, err := service.CleanupSubject(f.ctx, anonymouspg.CleanupSubjectRequest{TenantID: tenant, UserID: user, RunID: run})
			if err == nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.Recovery.CommandID == "" {
				t.Fatal("failed cleanup escaped rollback classification", err, out.Outcome)
			}
			assertCleanupNotApplied(t, f, tenant, user, out.Recovery.CommandID)
			if mode == "outbox" {
				var reached bool
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT is_called FROM public.cleanup_outbox_reached`).Scan(&reached); err != nil || !reached {
					t.Fatal("outbox failure oracle was never reached", err)
				}
			}
		})
	}
}

type cleanupObservedClock struct{ offset atomic.Int64 }

func (c *cleanupObservedClock) Now() time.Time {
	return time.Now().Add(time.Duration(c.offset.Load()))
}

func assertCleanupNotApplied(t *testing.T, f publicAnonymousFixture, tenant identity.TenantID, user identity.UserID, command identity.CommandID) {
	t.Helper()
	var state int16
	var status string
	var effects, audits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT a.state,u.status,(SELECT count(*) FROM identity.anonymous_disposals WHERE tenant_id=$1 AND user_id=$2)+(SELECT count(*) FROM anonymous_store.disposals WHERE tenant_id=$1 AND user_id=$2)+(SELECT count(*) FROM session_store.anonymous_disposals WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$3 AND r.outcome=$4),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$3) FROM anonymous_store.subjects a JOIN identity.users u USING(tenant_id,user_id) WHERE tenant_id=$1 AND user_id=$2`, string(tenant), string(user), mustExpiryCommandBytes(t, command), int64(audit.OutcomeSucceeded)).Scan(&state, &status, &effects, &audits, &events); err != nil || state != 1 || status != "active" || effects+audits+events != 0 {
		t.Fatal("cleanup partially committed despite failure", err, state, status, effects, audits, events)
	}
}

// C05: the actual wire COMMIT is lost before/after server acceptance. A fresh
// native service recovers the original random command without expired cookies,
// a regenerated snapshot, another command ID or replaying the disposal.
func TestNativeCleanupOriginalCommitRecovery(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(fmt.Sprintf("before=%t", before), func(t *testing.T) {
			f := newPublicAnonymousFixture(t)
			installCleanupHistory(t, f)
			tenant, user := cleanupGuest(t, f, 48)
			fault := &anonymousCommitFault{before: before, disposal: true}
			pool, err := database.Connect(f.ctx, database.Config{DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.DialFunc = fault.dial
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if err := pool.Close(ctx); err != nil {
					t.Error(err)
				}
			}()
			config := cleanupServiceConfig(t, f)
			config.Coordinator.LeaseDuration = 3 * time.Second
			service, err := anonymouspg.NewCleanupService(pool, config, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			run, _ := identity.NewCommandID()
			out, err := service.CleanupSubject(f.ctx, anonymouspg.CleanupSubjectRequest{TenantID: tenant, UserID: user, RunID: run})
			var unknown identity.UnknownCommitError
			if !errors.As(err, &unknown) || out.Outcome != identity.CommitOutcomeUnknown || out.Recovery.CommandID == "" || !fault.hit.Load() {
				t.Fatal("real COMMIT ambiguity was hidden or not reached", err, out.Outcome)
			}
			fresh, err := anonymouspg.NewCleanupService(f.pool, config, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			want := identity.CommitOutcomeCommitted
			if before {
				want = identity.CommitOutcomeNotCommitted
			}
			timer, tick := time.NewTimer(5*time.Second), time.NewTicker(25*time.Millisecond)
			defer timer.Stop()
			defer tick.Stop()
			for {
				recovered, err := fresh.RecoverCleanup(f.ctx, out.Recovery)
				if recovered.Outcome == want {
					if !before && err != nil {
						t.Fatal("committed original recovery failed", err)
					}
					if recovered.Recovery != out.Recovery {
						t.Fatal("recovery changed original command scope")
					}
					break
				}
				select {
				case <-timer.C:
					t.Fatal("original cleanup did not reconcile", err, recovered.Outcome)
				case <-f.ctx.Done():
					t.Fatal("owned cleanup recovery budget")
				case <-tick.C:
				}
			}
			if before {
				assertCleanupNotApplied(t, f, tenant, user, out.Recovery.CommandID)
			}
		})
	}
}
