//go:build integration

package anonymouspostgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	anonymouspg "github.com/faustbrian/go-identity/anonymous/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
)

func TestNativePublicAnonymousSelfDeletion(t *testing.T) {
	for _, group := range []string{"baseline", "siblings", "denials", "rollback", "contention", "commit"} {
		t.Run(group, func(t *testing.T) { testNativePublicAnonymousSelfDeletion(t, group) })
	}
}

func testNativePublicAnonymousSelfDeletion(t *testing.T, group string) {
	f := newPublicAnonymousFixture(t)
	ctx := f.ctx
	var source migrations.Source = riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "anonymous_risk", Version: 58}, Version: 59}, Version: 60}, Version: 61}
	history, err := source.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if _, err := f.pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal("selected protected risk history", err)
		}
	}
	var afterRetention func(context.Context, identity.RetentionPolicyInput) error
	retention, err := identity.NewPolicyEvaluator(identity.PolicySet{Authorize: anonymousPolicy{}, AssessRisk: func(context.Context, identity.RiskPolicyInput) (identity.RiskPolicyDecision, error) {
		return identity.RiskPolicyDecision{}, identity.ForbiddenError{}
	}, MapClaims: func(context.Context, identity.ClaimsPolicyInput) (identity.ClaimsPolicyDecision, error) {
		return identity.ClaimsPolicyDecision{}, identity.ForbiddenError{}
	}, Redact: func(context.Context, identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
		return identity.RedactionPolicyDecision{}, identity.ForbiddenError{}
	}, DecideRetention: func(_ context.Context, in identity.RetentionPolicyInput) (identity.RetentionPolicyDecision, error) {
		if in.OperationID != "identity.anonymous.delete" || in.ActorID != identity.ActorID(in.SubjectID) || in.Resource.Kind != "anonymous" || in.Resource.ID != string(in.SubjectID) {
			return identity.RetentionPolicyDecision{}, identity.ForbiddenError{}
		}
		if afterRetention != nil {
			if err := afterRetention(ctx, in); err != nil {
				return identity.RetentionPolicyDecision{}, err
			}
		}
		d := identity.RetentionAllow
		if in.LegalHold {
			d = identity.RetentionBlockLegalHold
		}
		return identity.RetentionPolicyDecision{Disposition: d, PolicyID: "anonymous-retention", PolicyVersion: 1, Reasons: []identity.PolicyReason{"self-request"}}, nil
	}}, identity.PolicyEvaluatorConfig{PolicyID: "anonymous-retention", PolicyVersion: 1, Reasons: []identity.PolicyReason{"self-request"}, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	validation := session.ServiceConfig{Profile: session.StorageStatefulOpaque, Clock: clock.System{}, MaximumDuration: 3 * time.Second, ClockUncertainty: time.Millisecond, Audience: f.config.Profile.Audience, LookupKeys: []session.DigestKey{f.lookupKey}}
	config := anonymouspg.DeletionConfig{Repository: f.config.Repository, Sessions: f.config.Sessions, Profile: f.config.Profile, Validation: validation, CSRFKeys: []session.CSRFKey{f.csrfKey}, Origins: f.config.Origins, Reasons: []string{"self-request"}, ConfigurationID: "anonymous-deletion-v1", PolicyID: "anonymous-delete", Retention: retention, RetentionPolicyVersion: 1, RequestKeys: f.config.RequestKeys, Coordinator: f.config.Coordinator, IntentKey: [32]byte{42}, ActiveEnvelopeKeyID: f.config.ActiveEnvelopeKeyID, Risk: riskpg.Config{Schema: "anonymous_risk", PolicyVersion: 1, EvidenceKeys: []risk.EvidenceKey{f.evidence}, EnvelopeKeys: map[string][]byte{"risk-input": bytes.Repeat([]byte{43}, 32)}, CurrentEnvelopeKey: "risk-input", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: f.riskPolicy, Keys: []risk.CounterDigestKey{f.counterKey}}}}
	service, err := anonymouspg.NewDeletionService(f.pool, config, f.keys)
	if err != nil {
		t.Fatal("public deletion constructor", err)
	}
	request := f.fresh()
	issued, err := f.service.Signin(ctx, request)
	if err != nil {
		t.Fatal("actual guest signin prerequisite", err)
	}
	spec, _ := issued.Session.Session.Bindings()
	if group == "siblings" {
		seedAnonymousDisposalSiblings(t, f, issued.Session.Session)
	}
	credential, err := session.NewCredential(session.CredentialCookie, issued.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := identity.NewIdempotencyKey([]byte("self-deletion-original"))
	r := anonymous.DeletionRequest{TenantID: spec.TenantID, Credential: credential, CSRFToken: issued.CSRFToken, ExpectedVersion: 1, Reason: "self-request", Origin: request.Origin, Network: request.Network, Device: request.Device, IdempotencyKey: key}
	type rateSource interface {
		DeletionRateSource(context.Context, anonymous.DeletionRequest) (identity.UserID, error)
	}
	var rateOwner rateSource
	if group == "baseline" {
		var ok bool
		rateOwner, ok = any(service).(rateSource)
		if !ok {
			t.Fatal("native deletion lacks possession-owned HTTP rate source")
		}
		user, err := rateOwner.DeletionRateSource(ctx, r)
		if err != nil || user != spec.UserID {
			t.Fatal("original guest possession did not select its actual rate subject", err)
		}
		bad := r
		bad.CSRFToken = session.CSRFToken{}
		if user, err := rateOwner.DeletionRateSource(ctx, bad); err == nil || user != "" {
			t.Fatal("unproven guest synchronizer selected a rate subject")
		}
		var disposals int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM anonymous_store.disposals`).Scan(&disposals); err != nil || disposals != 0 {
			t.Fatal("rate source performed deletion work", err)
		}
	}
	var deleter anonymous.Deleter = service
	result, err := deleter.Delete(ctx, r)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Recovery.RecordID != string(spec.UserID) || result.Recovery.CommandID == "" || result.Replayed {
		t.Fatal("public self-deletion did not commit", err, result.Outcome)
	}
	if rateOwner != nil {
		if user, err := rateOwner.DeletionRateSource(ctx, r); err != nil || user != spec.UserID {
			t.Fatal("self-revoked original custody lost its stable retry rate scope", err)
		}
	}
	reader, err := anonymouspg.NewSessionService(f.pool, anonymouspg.SessionServiceConfig{Repository: config.Repository, Sessions: config.Sessions, Profile: config.Profile, Validation: validation})
	if err != nil {
		t.Fatal(err)
	}
	guest, err := reader.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: credential})
	if err != nil || guest.Recognized {
		t.Fatal("deleted guest remains authenticated", err)
	}
	var status string
	var state int16
	var active, attrs, kernelEffects, lifecycleEffects, sessionEffects int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT u.status,a.state,(SELECT count(*) FROM session_store.sessions WHERE tenant_id=u.tenant_id AND user_id=u.user_id AND state='active'),(SELECT count(*) FROM identity.user_attributes WHERE tenant_id=u.tenant_id AND user_id=u.user_id),(SELECT count(*) FROM identity.anonymous_disposals WHERE tenant_id=u.tenant_id AND user_id=u.user_id),(SELECT count(*) FROM anonymous_store.disposals WHERE tenant_id=u.tenant_id AND user_id=u.user_id),(SELECT count(*) FROM session_store.anonymous_disposals WHERE tenant_id=u.tenant_id AND user_id=u.user_id) FROM identity.users u JOIN anonymous_store.subjects a USING(tenant_id,user_id) WHERE tenant_id=$1 AND user_id=$2`, string(spec.TenantID), string(spec.UserID)).Scan(&status, &state, &active, &attrs, &kernelEffects, &lifecycleEffects, &sessionEffects); err != nil || status != "anonymized" || state != int16(anonymous.StateAnonymized) || active != 0 || attrs != 0 || kernelEffects != 1 || lifecycleEffects != 1 || sessionEffects != 1 {
		t.Fatal("actual protected deletion owners disagree", err, status, state, active, attrs, kernelEffects, lifecycleEffects, sessionEffects)
	}
	if group == "siblings" {
		var sessions, families, revoked, revokedFamilies int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='revoked'),(SELECT count(*) FROM session_store.families WHERE tenant_id=$1 AND user_id=$2 AND state='revoked'),revoked_count,family_count FROM session_store.anonymous_disposals WHERE tenant_id=$1 AND user_id=$2`, string(spec.TenantID), string(spec.UserID)).Scan(&sessions, &families, &revoked, &revokedFamilies); err != nil || sessions != 18 || families != 19 || revoked != sessions || revokedFamilies != families {
			t.Fatal("disposal omitted a later-page, expired sibling or empty family", err, sessions, families, revoked, revokedFamilies)
		}
	}
	replayed, err := deleter.Delete(ctx, r)
	if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || !replayed.Replayed || replayed.Recovery != result.Recovery {
		t.Fatal("original revoked-session metadata replay failed", err, replayed.Outcome)
	}
	freshService, err := anonymouspg.NewDeletionService(f.pool, config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	recovery := anonymous.DeletionRecoveryRequest{Recovery: result.Recovery, Credential: credential, CSRFToken: r.CSRFToken, Origin: r.Origin, Network: r.Network, Device: r.Device}
	recovered, err := freshService.RecoverDeletion(ctx, recovery)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("fresh-instance original deletion recovery", err, recovered.Outcome)
	}
	if group == "siblings" {
		// Prunable live payload is not the retained outcome/possession authority.
		// Keep owner evidence and original encrypted preparation untouched.
		n, err := f.pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='revoked'`, string(spec.TenantID), string(spec.UserID))
		if err != nil || n.RowsAffected() != 18 {
			t.Fatal("owned revoked-session payload cleanup", err)
		}
		freshService, err = anonymouspg.NewDeletionService(f.pool, config, f.keys)
		if err != nil {
			t.Fatal(err)
		}
		recovered, err := freshService.RecoverDeletion(ctx, recovery)
		if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Recovery != result.Recovery {
			t.Fatal("live payload cleanup lost original-only outcome recovery", err, recovered.Outcome)
		}
		guest, err := reader.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: credential})
		if err != nil || guest.Recognized {
			t.Fatal("historical recovery restored guest authority", err)
		}
	}
	wrong, _ := session.NewToken(32)
	recovery.Credential, _ = session.NewCredential(session.CredentialCookie, wrong)
	if out, err := freshService.RecoverDeletion(ctx, recovery); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("foreign possession disclosed original command")
	}
	changed := r
	changed.Device = "other"
	if _, err := deleter.Delete(ctx, changed); err == nil {
		t.Fatal("changed keyed deletion intent admitted")
	}

	freshGuest := func(t *testing.T) (anonymous.DeletionRequest, session.Session) {
		t.Helper()
		request := f.fresh()
		issued, err := f.service.Signin(ctx, request)
		if err != nil {
			t.Fatal("fresh genuine guest", err)
		}
		spec, _ := issued.Session.Session.Bindings()
		credential, _ := session.NewCredential(session.CredentialCookie, issued.Session.Token)
		id, _ := identity.NewCommandID()
		key, _ := identity.NewIdempotencyKey([]byte(id))
		return anonymous.DeletionRequest{TenantID: spec.TenantID, Credential: credential, CSRFToken: issued.CSRFToken, ExpectedVersion: 1, Reason: "self-request", Origin: request.Origin, Network: request.Network, Device: request.Device, IdempotencyKey: key}, issued.Session.Session
	}
	assertActive := func(t *testing.T, r anonymous.DeletionRequest) {
		t.Helper()
		got, err := reader.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: r.Credential})
		if err != nil || !got.Recognized {
			t.Fatal("denied disposal changed active guest", err)
		}
	}
	if group == "denials" {
		for _, mode := range []string{"wrong-csrf", "wrong-version", "foreign-tenant", "origin", "reason", "held", "hold-race", "policy-outage"} {
			t.Run(mode, func(t *testing.T) {
				original, record := freshGuest(t)
				bad := original
				spec, _ := record.Bindings()
				switch mode {
				case "wrong-csrf":
					bad.CSRFToken, _ = session.NewCSRFToken()
				case "wrong-version":
					bad.ExpectedVersion = 2
				case "foreign-tenant":
					bad.TenantID = "other-tenant"
				case "origin":
					bad.Origin = "https://other.test"
				case "reason":
					bad.Reason = "unregistered"
				case "held":
					if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.users SET legal_hold=true,legal_hold_version=2 WHERE tenant_id=$1 AND user_id=$2`, string(spec.TenantID), string(spec.UserID)); err != nil {
						t.Fatal(err)
					}
				case "hold-race":
					afterRetention = func(ctx context.Context, in identity.RetentionPolicyInput) error {
						_, err := f.pool.Raw().Exec(ctx, `UPDATE identity.users SET legal_hold=true,legal_hold_version=2 WHERE tenant_id=$1 AND user_id=$2`, string(in.TenantID), string(in.SubjectID))
						return err
					}
					defer func() { afterRetention = nil }()
				case "policy-outage":
					afterRetention = func(context.Context, identity.RetentionPolicyInput) error { return identity.UnavailableError{} }
					defer func() { afterRetention = nil }()
				}
				out, err := deleter.Delete(ctx, bad)
				if err == nil || out.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("invalid self-deletion accepted", mode, err)
				}
				assertActive(t, original)
			})
		}
	}
	if group == "rollback" {
		for _, table := range []string{"audit.records", "public.outbox_messages"} {
			t.Run("late-rollback-"+table, func(t *testing.T) {
				r, record := freshGuest(t)
				spec, _ := record.Bindings()
				if _, err := f.pool.Raw().Exec(ctx, `CREATE SEQUENCE public.anonymous_disposal_reached;
CREATE FUNCTION public.anonymous_disposal_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM identity.anonymous_disposals WHERE user_id='`+string(spec.UserID)+`') OR
 NOT EXISTS(SELECT 1 FROM anonymous_store.disposals WHERE user_id='`+string(spec.UserID)+`') OR
 NOT EXISTS(SELECT 1 FROM session_store.anonymous_disposals WHERE user_id='`+string(spec.UserID)+`') THEN RAISE EXCEPTION 'fault missed protected effects'; END IF;
 PERFORM nextval('public.anonymous_disposal_reached'); RAISE EXCEPTION 'injected required disposal failure'; END $$;`); err != nil {
					t.Fatal(err)
				}
				condition := "NEW.action='identity.anonymous.delete' AND NEW.outcome=" + fmt.Sprint(audit.OutcomeSucceeded)
				if table == "public.outbox_messages" {
					condition = "NEW.topic='anonymous.deleted.v1'"
				}
				if _, err := f.pool.Raw().Exec(ctx, "CREATE TRIGGER anonymous_disposal_fault AFTER INSERT ON "+table+" FOR EACH ROW WHEN ("+condition+") EXECUTE FUNCTION public.anonymous_disposal_fault()"); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := f.pool.Raw().Exec(ctx, "DROP TRIGGER anonymous_disposal_fault ON "+table+";DROP FUNCTION public.anonymous_disposal_fault();DROP SEQUENCE public.anonymous_disposal_reached"); err != nil {
						t.Error("owned fault cleanup", err)
					}
				}()
				out, err := deleter.Delete(ctx, r)
				if err == nil || out.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("late failure lost known rollback", err, out.Outcome)
				}
				var reached bool
				if err := f.pool.Raw().QueryRow(ctx, `SELECT is_called FROM public.anonymous_disposal_reached`).Scan(&reached); err != nil || !reached {
					t.Fatal("rollback oracle missed real effects", err)
				}
				assertActive(t, r)
				var count int
				if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.anonymous_disposals WHERE user_id=$1)+(SELECT count(*) FROM anonymous_store.disposals WHERE user_id=$1)+(SELECT count(*) FROM session_store.anonymous_disposals WHERE user_id=$1)`, string(spec.UserID)).Scan(&count); err != nil || count != 0 {
					t.Fatal("required failure leaked partial disposal", err)
				}
			})
		}
	}
	if group == "contention" {
		t.Run("same-key-contention", func(t *testing.T) {
			r, record := freshGuest(t)
			spec, _ := record.Bindings()
			type answer struct {
				out anonymous.DeletionResult
				err error
			}
			answers := make(chan answer, 4)
			start := make(chan struct{})
			var done sync.WaitGroup
			for range 4 {
				done.Add(1)
				go func() { defer done.Done(); <-start; out, err := deleter.Delete(ctx, r); answers <- answer{out, err} }()
			}
			close(start)
			done.Wait()
			close(answers)
			commits := 0
			for a := range answers {
				if a.out.Outcome == identity.CommitOutcomeCommitted && a.err == nil {
					commits++
				} else if a.out.Outcome != identity.CommitOutcomeInProgress {
					t.Fatal("same original concurrent deletion failed", a.err, a.out.Outcome)
				}
			}
			if commits == 0 {
				t.Fatal("no exact original deletion won")
			}
			var n int
			if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM anonymous_store.disposals WHERE user_id=$1`, string(spec.UserID)).Scan(&n); err != nil || n != 1 {
				t.Fatal("contention duplicated disposal", err)
			}
		})
	}
	if group == "commit" {
		for _, before := range []bool{true, false} {
			t.Run(fmt.Sprintf("commit-fault-before=%t", before), func(t *testing.T) {
				r, record := freshGuest(t)
				spec, _ := record.Bindings()
				fault := &anonymousCommitFault{before: before, disposal: true}
				faultPool, err := database.Connect(ctx, database.Config{DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
					c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
					c.ConnConfig.DialFunc = fault.dial
					return nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
					defer stop()
					if err := faultPool.Close(bounded); err != nil {
						t.Error(err)
					}
				}()
				faultConfig := config
				faultConfig.Coordinator.LeaseDuration = 3 * time.Second
				faultService, err := anonymouspg.NewDeletionService(faultPool, faultConfig, f.keys)
				if err != nil {
					t.Fatal(err)
				}
				out, err := faultService.Delete(ctx, r)
				var unknown identity.UnknownCommitError
				if !errors.As(err, &unknown) || out.Outcome != identity.CommitOutcomeUnknown || !fault.hit.Load() {
					t.Fatal("actual COMMIT lost unknown semantics", err, out.Outcome)
				}
				q := anonymous.DeletionRecoveryRequest{Recovery: out.Recovery, Credential: r.Credential, CSRFToken: r.CSRFToken, Origin: r.Origin, Network: r.Network, Device: r.Device}
				want := identity.CommitOutcomeCommitted
				if before {
					want = identity.CommitOutcomeNotCommitted
				}
				deadline := time.NewTimer(5 * time.Second)
				defer deadline.Stop()
				tick := time.NewTicker(25 * time.Millisecond)
				defer tick.Stop()
				for {
					recovered, err := service.RecoverDeletion(ctx, q)
					if recovered.Outcome == want {
						if !before && err != nil {
							t.Fatal(err)
						}
						break
					}
					select {
					case <-deadline.C:
						t.Fatal("actual deletion did not reconcile", err, recovered.Outcome)
					case <-ctx.Done():
						t.Fatal("recovery budget")
					case <-tick.C:
					}
				}
				var n int
				if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM anonymous_store.disposals WHERE user_id=$1`, string(spec.UserID)).Scan(&n); err != nil || before && n != 0 || !before && n != 1 {
					t.Fatal("recovered disposal disagrees with actual state", err)
				}
				if before {
					assertActive(t, r)
				} else {
					got, err := reader.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: r.Credential})
					if err != nil || got.Recognized {
						t.Fatal("committed unknown guest still active", err)
					}
				}
			})
		}
	}
}

// Seed complete historical owner rows from a genuinely issued anonymous source.
// These are storage fixtures, not a claim that metadata construction issues a
// session. The public repository must decode every row before disposal runs.
func seedAnonymousDisposalSiblings(t *testing.T, f publicAnonymousFixture, original session.Session) {
	t.Helper()
	base, err := original.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	repository, err := sessionpg.NewRepository(f.pool, f.config.Sessions)
	if err != nil {
		t.Fatal(err)
	}
	var originalWire []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT record::text FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2`, string(base.TenantID), base.SessionID).Scan(&originalWire); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 17; i++ {
		s := base
		s.SessionID, s.FamilyID = fmt.Sprintf("disposal-sibling-%02d", i), fmt.Sprintf("disposal-family-%02d", i)
		if i == 0 {
			s.IssuedAt = s.IssuedAt.Add(-48 * time.Hour)
			s.LastActivityAt = s.IssuedAt
			s.Authentication.AnonymousAt = s.IssuedAt
		}
		token, err := session.NewToken(32)
		if err != nil {
			t.Fatal(err)
		}
		s.Lookup, err = token.Digest(f.lookupKey, string(s.TenantID))
		if err != nil {
			t.Fatal(err)
		}
		vector, err := s.Authority.Bindings()
		if err != nil {
			t.Fatal(err)
		}
		keys, err := sessionpg.SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
		if err != nil {
			t.Fatal(err)
		}
		vector.Session.ScopeKey, vector.SessionFamily.ScopeKey = keys.Session, keys.Family
		s.Authority, err = session.NewAuthoritySnapshot(vector)
		if err != nil {
			t.Fatal(err)
		}
		csrf, err := session.NewCSRFToken()
		if err != nil {
			t.Fatal(err)
		}
		csrfState, err := csrf.Digest(f.csrfKey, session.CSRFBinding{TenantID: s.TenantID, SessionID: s.SessionID, SessionVersion: s.Version})
		if err != nil {
			t.Fatal(err)
		}
		record, err := session.NewSessionWithCSRF(s, csrfState)
		if err != nil {
			t.Fatal("historical sibling structural validation", err)
		}
		lifetime, err := record.Lifetime(s.LastActivityAt)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(originalWire, &fields); err != nil {
			t.Fatal(err)
		}
		csrfSpec, err := csrfState.Bindings()
		if err != nil {
			t.Fatal(err)
		}
		for name, value := range map[string]any{"SessionID": s.SessionID, "FamilyID": s.FamilyID, "Authority": vector, "Lookup": s.Lookup, "Authentication": s.Authentication, "IssuedAt": s.IssuedAt.UTC(), "LastActivityAt": s.LastActivityAt.UTC(), "CSRF": csrfSpec} {
			fields[name], err = json.Marshal(value)
			if err != nil {
				t.Fatal("historical sibling storage projection", name, err)
			}
		}
		wire, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO session_store.families(tenant_id,user_id,family_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4)`, string(s.TenantID), string(s.UserID), s.FamilyID, s.IssuedAt.UTC().Format("2006-01-02T15:04:05.000000000Z")); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO session_store.sessions(tenant_id,user_id,session_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES($1,$2,$3,$4,1,1,'active',$5,$6,$7,$8::jsonb)`, string(s.TenantID), string(s.UserID), s.SessionID, s.FamilyID, int64(s.Lookup.KeyVersion), s.Lookup.Sum[:], lifetime.ExpiresAt.UTC().Format("2006-01-02T15:04:05.000000000Z"), wire); err != nil {
			t.Fatal(err)
		}
		stored, err := repository.Lookup(f.ctx, s.TenantID, s.Lookup)
		if err != nil || stored.Session == (session.Session{}) {
			t.Fatal("historical sibling does not satisfy real stored-row contract", err)
		}
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO session_store.families(tenant_id,user_id,family_id,version,state,issued_at) VALUES($1,$2,'disposal-empty-family',1,'active',$3)`, string(base.TenantID), string(base.UserID), base.IssuedAt.UTC().Format("2006-01-02T15:04:05.000000000Z")); err != nil {
		t.Fatal(err)
	}
}
