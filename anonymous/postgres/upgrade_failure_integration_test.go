//go:build integration

package anonymouspostgres_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	anonymouspg "github.com/faustbrian/go-identity/anonymous/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

type nativeUpgradeJourney struct {
	f       publicAnonymousFixture
	config  anonymouspg.UpgradeConfig
	service *anonymouspg.UpgradeService
	request anonymous.UpgradeRequest
	guest   session.Session
	target  anonymousUpgradeTarget
}

func TestNativeAnonymousUpgradeKeepsTargetAndRetainsExplicitDecision(t *testing.T) {
	j := newNativeUpgradeJourney(t)
	r := j.request
	r.Plan.Conflicts = []anonymous.Conflict{{Field: "profile.display_name", Disposition: anonymous.KeepTarget}}
	var before string
	if err := j.f.pool.Raw().QueryRow(j.f.ctx, `SELECT row_to_json(u)::text FROM identity.users u WHERE tenant_id=$1 AND user_id=$2`, string(r.TenantID), string(upgradeTargetID)).Scan(&before); err != nil {
		t.Fatal(err)
	}
	out, err := j.service.Upgrade(j.f.ctx, r)
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.Replayed || out.Session.Token == (session.Token{}) {
		t.Fatal("explicit KeepTarget public upgrade did not complete", err, out.Outcome)
	}
	var after, field string
	var fields, decisions int
	var disposition int16
	if err := j.f.pool.Raw().QueryRow(j.f.ctx, `SELECT row_to_json(u)::text,a.merge_fields[1],a.merge_dispositions[1],cardinality(a.merge_fields),cardinality(a.merge_dispositions) FROM identity.users u JOIN anonymous_store.upgrades a ON a.tenant_id=u.tenant_id AND a.target_user_id=u.user_id WHERE u.tenant_id=$1 AND u.user_id=$2`, string(r.TenantID), string(upgradeTargetID)).Scan(&after, &field, &disposition, &fields, &decisions); err != nil || before != after || field != "profile.display_name" || disposition != int16(anonymous.KeepTarget) || fields != 1 || decisions != 1 {
		t.Fatal("KeepTarget changed target data or lost its retained decision", err)
	}
	fresh, err := anonymouspg.NewUpgradeService(j.f.pool, j.config, j.f.keys)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := fresh.Upgrade(j.f.ctx, r)
	if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || !replayed.Replayed || replayed.Preparation != out.Preparation || replayed.Recovery != out.Recovery || replayed.Session.Token != (session.Token{}) || replayed.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("explicit decision replay changed outcome or redelivered", err, replayed.Outcome)
	}
}

func TestNativeAnonymousUpgradeTerminalReplayRetainsLookupAndCSRFKeys(t *testing.T) {
	j := newNativeUpgradeJourney(t)
	out, err := j.service.Upgrade(j.f.ctx, j.request)
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real upgrade prerequisite", err, out.Outcome)
	}
	lookup, err := session.NewDigestKey(2, bytes.Repeat([]byte{101}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFKey(2, bytes.Repeat([]byte{102}, 32))
	if err != nil {
		t.Fatal(err)
	}
	config := j.config
	config.Guest.Validation.LookupKeys = []session.DigestKey{lookup, j.f.lookupKey}
	config.Target.Validation.LookupKeys = []session.DigestKey{lookup, j.f.lookupKey}
	config.Guest.CSRFKeys = []session.CSRFKey{csrf, j.f.csrfKey}
	config.TargetCSRFKeys = []session.CSRFKey{csrf, j.f.csrfKey}
	fresh, err := anonymouspg.NewUpgradeService(j.f.pool, config, j.f.keys)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := fresh.Upgrade(j.f.ctx, j.request)
	if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || !replayed.Replayed || replayed.Preparation != out.Preparation || replayed.Recovery != out.Recovery || replayed.Session.Token != (session.Token{}) || replayed.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("retained original transport keys changed retry intent", err, replayed.Outcome)
	}
}

func TestNativeAnonymousUpgradeRechecksFactsAfterRetention(t *testing.T) {
	for _, mode := range []string{"guest-hold", "target-ban", "target-session", "factor-generation"} {
		t.Run(mode, func(t *testing.T) {
			var j nativeUpgradeJourney
			j = newNativeUpgradeJourney(t, func(ctx context.Context, in identity.RetentionPolicyInput) error {
				sql := `UPDATE identity.users SET legal_hold=true,legal_hold_version=legal_hold_version+1 WHERE tenant_id=$1 AND user_id=$2`
				id := in.SubjectID
				switch mode {
				case "target-ban":
					sql = `UPDATE identity.users SET status='banned',version=version+1,authority_version=authority_version+1 WHERE tenant_id=$1 AND user_id=$2`
					id = upgradeTargetID
				case "target-session":
					sql = `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2`
					id = upgradeTargetID
				case "factor-generation":
					sql = `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`
					id = upgradeTargetID
				}
				_, err := j.f.pool.Raw().Exec(ctx, sql, string(in.TenantID), string(id))
				return err
			})
			out, err := j.service.Upgrade(j.f.ctx, j.request)
			if err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Session.Token != (session.Token{}) || out.CSRFToken != (session.CSRFToken{}) {
				t.Fatal("stale pre-retention facts authorized upgrade", err, out.Outcome)
			}
			j.assertNoUpgrade(t)
		})
	}
}

func TestNativeAnonymousUpgradeRecoveryRetainsPossessionAfterGuestPayloadPruning(t *testing.T) {
	j := newNativeUpgradeJourney(t)
	out, err := j.service.Upgrade(j.f.ctx, j.request)
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual upgrade prerequisite", err, out.Outcome)
	}
	guest, _ := j.guest.Bindings()
	n, err := j.f.pool.Raw().Exec(j.f.ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='revoked'`, string(guest.TenantID), string(guest.UserID))
	if err != nil || n.RowsAffected() != 1 {
		t.Fatal("owned revoked guest payload cleanup", err)
	}
	fresh, err := anonymouspg.NewUpgradeService(j.f.pool, j.config, j.f.keys)
	if err != nil {
		t.Fatal(err)
	}
	original := j.recovery(out)
	recovered, err := fresh.RecoverUpgrade(j.f.ctx, original)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || !recovered.Replayed || recovered.Preparation != out.Preparation || recovered.Recovery != out.Recovery || recovered.Session.Token != (session.Token{}) || recovered.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("pruned live payload lost metadata-only original recovery", err, recovered.Outcome)
	}
	for _, mode := range []string{"guest-cookie", "guest-csrf", "target-cookie", "target-csrf", "device", "command"} {
		t.Run(mode, func(t *testing.T) {
			r := original
			switch mode {
			case "guest-cookie":
				token, _ := session.NewToken(32)
				r.Guest, _ = session.NewCredential(session.CredentialCookie, token)
			case "guest-csrf":
				r.GuestCSRF, _ = session.NewCSRFToken()
			case "target-cookie":
				token, _ := session.NewToken(32)
				wire, _ := token.Reveal()
				r.TargetSession = auth.NewBearerCredential(wire)
			case "target-csrf":
				r.TargetCSRF, _ = session.NewCSRFToken()
			case "device":
				r.Device = "other"
			case "command":
				r.Recovery.CommandID, _ = identity.NewCommandID()
			}
			rejected, err := fresh.RecoverUpgrade(j.f.ctx, r)
			if err == nil || rejected.Outcome == identity.CommitOutcomeCommitted || rejected.Session.Token != (session.Token{}) || rejected.CSRFToken != (session.CSRFToken{}) {
				t.Fatal("foreign possession/scope disclosed historical outcome", err, rejected.Outcome)
			}
		})
	}
	reader, err := anonymouspg.NewSessionService(j.f.pool, anonymouspg.SessionServiceConfig{Repository: j.config.Guest.Repository, Sessions: j.config.Guest.Sessions, Profile: j.config.Guest.Profile, Validation: j.config.Guest.Validation})
	if err != nil {
		t.Fatal(err)
	}
	read, err := reader.Get(j.f.ctx, session.GetRequest{TenantID: guest.TenantID, Credential: j.request.Guest})
	if err != nil || read.Recognized {
		t.Fatal("historical recovery restored guest authentication", err)
	}
}

func newNativeUpgradeJourney(t *testing.T, after ...func(context.Context, identity.RetentionPolicyInput) error) nativeUpgradeJourney {
	t.Helper()
	f := newPublicAnonymousFixture(t)
	signin := f.fresh()
	issued, err := f.service.Signin(f.ctx, signin)
	if err != nil {
		t.Fatal(err)
	}
	guest, _ := issued.Session.Session.Bindings()
	target := newAnonymousUpgradeTarget(t, f, guest.Remember)
	proof := target.verify(t, f)
	config := anonymousUpgradeConfiguration(t, f, target, after...)
	service, err := anonymouspg.NewUpgradeService(f.pool, config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := anonymouspg.NewRepository(f.pool, config.Guest.Repository)
	if err != nil {
		t.Fatal(err)
	}
	source, err := repository.Read(f.ctx, anonymous.SubjectQuery{TenantID: guest.TenantID, UserID: guest.UserID})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, issued.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := identity.NewCommandID()
	key, _ := identity.NewIdempotencyKey([]byte(id))
	caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: authorization.TenantID(guest.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(upgradeTargetID)}, Action: "identity.anonymous.upgrade", Resource: authorization.Resource{Type: "anonymous", ID: authorization.ResourceID(guest.UserID)}}}
	r := anonymous.UpgradeRequest{TenantID: guest.TenantID, TargetSession: target.bearer, TargetProof: proof, TargetCSRF: target.csrf, Guest: credential, GuestCSRF: issued.CSRFToken, Plan: anonymous.MergePlan{Source: source, Target: identity.SubjectID(upgradeTargetID)}, Remember: guest.Remember, Caller: caller, Origin: signin.Origin, Network: signin.Network, Device: signin.Device, IdempotencyKey: key}
	return nativeUpgradeJourney{f, config, service, r, issued.Session.Session, target}
}

func (j nativeUpgradeJourney) assertNoUpgrade(t *testing.T) {
	t.Helper()
	guest, _ := j.guest.Bindings()
	var state, kernelEffects, anonymousEffects, sessionEffects, targetSessions, proofUses, capabilityUses int
	if err := j.f.pool.Raw().QueryRow(j.f.ctx, `SELECT state,
 (SELECT count(*) FROM identity.anonymous_disposals WHERE tenant_id=$1 AND user_id=$2),
 (SELECT count(*) FROM anonymous_store.upgrades WHERE tenant_id=$1 AND user_id=$2),
 (SELECT count(*) FROM session_store.anonymous_disposals WHERE tenant_id=$1 AND user_id=$2),
 (SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$3 AND session_id<>'permanent-target-session'),
 (SELECT count(*) FROM identity_password.reauthentication_records WHERE tenant_id=$1 AND user_id=$3 AND consumed_command_id IS NOT NULL),
 (SELECT coalesce(sum(uses),0) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.anonymous.upgrade')
 FROM anonymous_store.subjects WHERE tenant_id=$1 AND user_id=$2`, string(guest.TenantID), string(guest.UserID), string(upgradeTargetID)).Scan(&state, &kernelEffects, &anonymousEffects, &sessionEffects, &targetSessions, &proofUses, &capabilityUses); err != nil || state != int(anonymous.StateActive) || kernelEffects != 0 || anonymousEffects != 0 || sessionEffects != 0 || targetSessions != 0 || proofUses != 0 || capabilityUses != 0 {
		t.Fatal("denied/rolled-back upgrade changed protected owners", err, state, kernelEffects, anonymousEffects, sessionEffects, targetSessions, proofUses, capabilityUses)
	}
}

func (j nativeUpgradeJourney) recovery(out anonymous.UpgradeResult) anonymous.UpgradeRecoveryRequest {
	r := j.request
	return anonymous.UpgradeRecoveryRequest{Preparation: out.Preparation, Recovery: out.Recovery, TargetSession: r.TargetSession, TargetCSRF: r.TargetCSRF, Guest: r.Guest, GuestCSRF: r.GuestCSRF, Origin: r.Origin, Network: r.Network, Device: r.Device}
}

func TestNativeAnonymousUpgradeDeniesForeignAndChangedAuthority(t *testing.T) {
	for _, mode := range []string{"guest-cookie", "guest-csrf", "target-cookie", "target-csrf", "proof", "source-version", "origin", "tenant", "remember", "transfer", "guest-held", "target-blocked", "target-session-revoked", "factor-unknown"} {
		t.Run(mode, func(t *testing.T) {
			j := newNativeUpgradeJourney(t)
			r := j.request
			guest, _ := j.guest.Bindings()
			switch mode {
			case "guest-cookie":
				token, _ := session.NewToken(32)
				r.Guest, _ = session.NewCredential(session.CredentialCookie, token)
			case "guest-csrf":
				r.GuestCSRF, _ = session.NewCSRFToken()
			case "target-cookie":
				token, _ := session.NewToken(32)
				wire, _ := token.Reveal()
				r.TargetSession = auth.NewBearerCredential(wire)
			case "target-csrf":
				r.TargetCSRF, _ = session.NewCSRFToken()
			case "proof":
				id, _ := identity.NewSubjectID()
				r.TargetProof.Proof.ID = auth.ProofID(id)
			case "source-version":
				source, _ := r.Plan.Source.Record()
				source.Version++
				r.Plan.Source, _ = anonymous.NewAnonymousSubject(source)
			case "origin":
				r.Origin = "https://foreign.example.test"
			case "tenant":
				r.TenantID = "tenant-a"
			case "remember":
				selected, _ := r.Remember.Bindings()
				if selected.Choice == session.BrowserSession {
					selected.Choice = session.PersistentSession
				} else {
					selected.Choice = session.BrowserSession
				}
				r.Remember, _ = session.NewRememberPolicy(selected)
			case "transfer":
				r.Plan.Conflicts = []anonymous.Conflict{{Field: "profile.display_name", Disposition: anonymous.KeepSource}}
			case "guest-held":
				if _, err := j.f.pool.Raw().Exec(j.f.ctx, `UPDATE identity.users SET legal_hold=true,legal_hold_version=legal_hold_version+1 WHERE tenant_id=$1 AND user_id=$2`, string(r.TenantID), string(guest.UserID)); err != nil {
					t.Fatal(err)
				}
			case "target-blocked":
				if _, err := j.f.pool.Raw().Exec(j.f.ctx, `UPDATE identity.users SET status='banned',version=version+1,authority_version=authority_version+1 WHERE tenant_id=$1 AND user_id=$2`, string(r.TenantID), string(upgradeTargetID)); err != nil {
					t.Fatal(err)
				}
			case "target-session-revoked":
				if _, err := j.f.pool.Raw().Exec(j.f.ctx, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND session_id='permanent-target-session'`, string(r.TenantID)); err != nil {
					t.Fatal(err)
				}
			case "factor-unknown":
				if _, err := j.f.pool.Raw().Exec(j.f.ctx, `DELETE FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, string(r.TenantID), string(upgradeTargetID)); err != nil {
					t.Fatal(err)
				}
			}
			out, err := j.service.Upgrade(j.f.ctx, r)
			if err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Session.Token != (session.Token{}) || out.CSRFToken != (session.CSRFToken{}) {
				t.Fatal("invalid authority upgraded guest", err, out.Outcome)
			}
			j.assertNoUpgrade(t)
		})
	}
}

func TestNativeAnonymousUpgradeRequiredEffectsRollbackAllOwners(t *testing.T) {
	for _, table := range []string{"audit.records", "public.outbox_messages"} {
		t.Run(table, func(t *testing.T) {
			j := newNativeUpgradeJourney(t)
			if _, err := j.f.pool.Raw().Exec(j.f.ctx, `CREATE SEQUENCE public.upgrade_fault_reached;
CREATE FUNCTION public.upgrade_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
	IF NOT EXISTS(SELECT 1 FROM anonymous_store.upgrades) THEN RETURN NEW; END IF;
 IF NOT EXISTS(SELECT 1 FROM identity.anonymous_disposals WHERE purpose='identity.anonymous.upgrade') OR
 NOT EXISTS(SELECT 1 FROM anonymous_store.upgrades) OR
 NOT EXISTS(SELECT 1 FROM session_store.anonymous_disposals WHERE purpose='identity.anonymous.upgrade') OR
 NOT EXISTS(SELECT 1 FROM identity_password.reauthentication_records WHERE consumed_command_id IS NOT NULL) THEN RAISE EXCEPTION 'fault missed protected effects'; END IF;
 PERFORM nextval('public.upgrade_fault_reached'); RAISE EXCEPTION 'injected required upgrade failure'; END $$;`); err != nil {
				t.Fatal(err)
			}
			condition := "NEW.action='identity.anonymous.upgrade' AND NEW.outcome=" + fmt.Sprint(audit.OutcomeSucceeded)
			if table == "public.outbox_messages" {
				condition = "NEW.topic='anonymous.upgraded.v1'"
			}
			// The actual function distinguishes issuance-only preparation without
			// weakening the final rollback oracle for any protected owner.
			if _, err := j.f.pool.Raw().Exec(j.f.ctx, "CREATE TRIGGER upgrade_fault AFTER INSERT ON "+table+" FOR EACH ROW WHEN ("+condition+") EXECUTE FUNCTION public.upgrade_fault()"); err != nil {
				t.Fatal(err)
			}
			out, err := j.service.Upgrade(j.f.ctx, j.request)
			if err == nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.Session.Token != (session.Token{}) || out.CSRFToken != (session.CSRFToken{}) {
				t.Fatal("required failure escaped upgrade rollback", err, out.Outcome)
			}
			var hit bool
			if err := j.f.pool.Raw().QueryRow(j.f.ctx, `SELECT is_called FROM public.upgrade_fault_reached`).Scan(&hit); err != nil || !hit {
				t.Fatal("required failure did not reach actual protected effects", err)
			}
			j.assertNoUpgrade(t)
		})
	}
}

func TestNativeAnonymousUpgradeTerminalReplayOutlivesOriginalGrant(t *testing.T) {
	j := newNativeUpgradeJourney(t)
	out, err := j.service.Upgrade(j.f.ctx, j.request)
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine upgrade prerequisite", err, out.Outcome)
	}
	var expires time.Time
	if err := j.f.pool.Raw().QueryRow(j.f.ctx, `SELECT expires_at FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.anonymous.upgrade' AND state='finalized'`, string(j.request.TenantID)).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	// Exercise real exclusive signed expiry, not a replacement clock, a forged
	// session observation or artificially renewed preparation.
	timer := time.NewTimer(time.Until(expires.Add(25 * time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-j.f.ctx.Done():
		t.Fatal("original grant expiry budget")
	}
	fresh, err := anonymouspg.NewUpgradeService(j.f.pool, j.config, j.f.keys)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := fresh.Upgrade(j.f.ctx, j.request)
	if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || !replayed.Replayed || replayed.Preparation != out.Preparation || replayed.Recovery != out.Recovery || replayed.Session.Token != (session.Token{}) || replayed.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("expired original grant lost terminal metadata or redelivered", err, replayed.Outcome)
	}
	recovered, err := fresh.RecoverUpgrade(j.f.ctx, j.recovery(out))
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || !recovered.Replayed || recovered.Session.Token != (session.Token{}) || recovered.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("expired grant prevents metadata-only recovery", err, recovered.Outcome)
	}
	var n int
	if err := j.f.pool.Raw().QueryRow(j.f.ctx, `SELECT count(*) FROM anonymous_store.upgrades`).Scan(&n); err != nil || n != 1 {
		t.Fatal("expired grant replay repeated mutation", err, n)
	}
}

func TestNativeAnonymousUpgradeUnknownIssuanceCommitRetainsOriginal(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(fmt.Sprint(before), func(t *testing.T) {
			j := newNativeUpgradeJourney(t)
			fault := &anonymousCommitFault{before: before, issuance: true}
			pool, err := database.Connect(j.f.ctx, database.Config{DSN: j.f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = j.f.pool.Raw().Config().ConnConfig.Database
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
			config := j.config
			config.Guest.Coordinator.LeaseDuration = 3 * time.Second
			service, err := anonymouspg.NewUpgradeService(pool, config, j.f.keys)
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.Upgrade(j.f.ctx, j.request)
			var unknown identity.UnknownCommitError
			if !errors.As(err, &unknown) || unknown.CommandID != out.Preparation.CommandID || out.Preparation.CommandID == out.Recovery.CommandID || out.Outcome != identity.CommitOutcomeUnknown || !fault.hit.Load() || out.Session.Token != (session.Token{}) || out.CSRFToken != (session.CSRFToken{}) {
				t.Fatal("lost issuance COMMIT lost its original command custody", err, out.Outcome, fault.hit.Load())
			}
			j.assertNoUpgrade(t)
			var grants int
			if err := j.f.pool.Raw().QueryRow(j.f.ctx, `SELECT count(*) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.anonymous.upgrade'`, string(j.request.TenantID)).Scan(&grants); err != nil || before && grants != 0 || !before && grants != 1 {
				t.Fatal("actual issued grant disagrees with transport fault", err, grants)
			}
			// Recovery observes only the original phases. A committed issuance is
			// not a committed upgrade, and recovery must not start the second phase.
			recovered, recoveryErr := j.service.RecoverUpgrade(j.f.ctx, j.recovery(out))
			if recovered.Outcome == identity.CommitOutcomeCommitted || recovered.Session.Token != (session.Token{}) || recovered.CSRFToken != (session.CSRFToken{}) {
				t.Fatal("issuance-only recovery executed or revealed an upgrade")
			}
			j.assertNoUpgrade(t)
			if before {
				ctx, stop := context.WithTimeout(j.f.ctx, 5*time.Second)
				defer stop()
				tick := time.NewTicker(25 * time.Millisecond)
				defer tick.Stop()
				for recovered.Outcome != identity.CommitOutcomeNotCommitted {
					select {
					case <-ctx.Done():
						t.Fatal("original uncommitted issuance did not reconcile", recovered.Outcome, recoveryErr)
					case <-tick.C:
					}
					recovered, recoveryErr = j.service.RecoverUpgrade(ctx, j.recovery(out))
				}
				j.assertNoUpgrade(t)
			} else {
				// Same-key resumption may consume the ORIGINAL committed grant,
				// but a different invocation cannot redeliver the lost prospective
				// session. It must not sign or issue a replacement capability.
				replayed, err := j.service.Upgrade(j.f.ctx, j.request)
				if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || !replayed.Replayed || replayed.Preparation != out.Preparation || replayed.Recovery != out.Recovery || replayed.Session.Token != (session.Token{}) || replayed.CSRFToken != (session.CSRFToken{}) {
					t.Fatal("original issuance resumption lost custody or redelivered", err, replayed.Outcome)
				}
				var uses int
				if err := j.f.pool.Raw().QueryRow(j.f.ctx, `SELECT count(*),coalesce(sum(uses),0) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.anonymous.upgrade'`, string(j.request.TenantID)).Scan(&grants, &uses); err != nil || grants != 1 || uses != 1 {
					t.Fatal("resumption replaced or failed to consume original grant", err, grants, uses)
				}
			}
		})
	}
}

func TestNativeAnonymousUpgradeUnknownFinalCommitRecoversOriginal(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(fmt.Sprint(before), func(t *testing.T) {
			j := newNativeUpgradeJourney(t)
			fault := &anonymousCommitFault{before: before, disposal: true}
			pool, err := database.Connect(j.f.ctx, database.Config{DSN: j.f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = j.f.pool.Raw().Config().ConnConfig.Database
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
			config := j.config
			config.Guest.Coordinator.LeaseDuration = 3 * time.Second
			service, err := anonymouspg.NewUpgradeService(pool, config, j.f.keys)
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.Upgrade(j.f.ctx, j.request)
			var unknown identity.UnknownCommitError
			if !errors.As(err, &unknown) || unknown.CommandID != out.Recovery.CommandID || out.Outcome != identity.CommitOutcomeUnknown || !fault.hit.Load() || out.Session.Token != (session.Token{}) || out.CSRFToken != (session.CSRFToken{}) {
				t.Fatal("lost final COMMIT changed unknown custody", err, out.Outcome, fault.hit.Load())
			}
			want := identity.CommitOutcomeCommitted
			if before {
				want = identity.CommitOutcomeNotCommitted
			}
			deadline := time.NewTimer(5 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(25 * time.Millisecond)
			defer tick.Stop()
			for {
				recovered, err := j.service.RecoverUpgrade(j.f.ctx, j.recovery(out))
				if recovered.Outcome == want {
					if !before && err != nil {
						t.Fatal(err)
					}
					if !recovered.Replayed || recovered.Session.Token != (session.Token{}) || recovered.CSRFToken != (session.CSRFToken{}) {
						t.Fatal("unknown recovery revealed credential")
					}
					break
				}
				select {
				case <-deadline.C:
					t.Fatal("original final command did not reconcile", err, recovered.Outcome)
				case <-j.f.ctx.Done():
					t.Fatal("recovery budget")
				case <-tick.C:
				}
			}
			if before {
				j.assertNoUpgrade(t)
			} else {
				var n int
				if err := j.f.pool.Raw().QueryRow(j.f.ctx, `SELECT count(*) FROM anonymous_store.upgrades`).Scan(&n); err != nil || n != 1 {
					t.Fatal("recovery disagrees with actual upgrade", err, n)
				}
			}
		})
	}
}

func TestNativeAnonymousUpgradeCompetingCommandsCannotConsumeTwice(t *testing.T) {
	j := newNativeUpgradeJourney(t)
	a, b := j.request, j.request
	id, _ := identity.NewCommandID()
	b.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte(id))
	start := make(chan struct{})
	results := make(chan anonymous.UpgradeResult, 2)
	var wg sync.WaitGroup
	for _, r := range []anonymous.UpgradeRequest{a, b} {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; out, _ := j.service.Upgrade(j.f.ctx, r); results <- out }()
	}
	close(start)
	wg.Wait()
	close(results)
	committed, delivered := 0, 0
	for out := range results {
		if out.Outcome == identity.CommitOutcomeCommitted {
			committed++
		}
		if out.Session.Token != (session.Token{}) {
			delivered++
		}
	}
	if committed != 1 || delivered != 1 {
		t.Fatal("competing upgrade did not have exactly one winner", committed, delivered)
	}
	var transitions, proofs, uses int
	if err := j.f.pool.Raw().QueryRow(j.f.ctx, `SELECT (SELECT count(*) FROM anonymous_store.upgrades),(SELECT count(*) FROM identity_password.reauthentication_records WHERE consumed_command_id IS NOT NULL),(SELECT coalesce(sum(uses),0) FROM public.capability_identity_one_use WHERE purpose='identity.anonymous.upgrade')`).Scan(&transitions, &proofs, &uses); err != nil || transitions != 1 || proofs != 1 || uses != 1 {
		t.Fatal("competing commands duplicated protected effects", err, transitions, proofs, uses)
	}
}
