//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// These fixtures exercise real kernel SQL/one-time transaction phases, not
// production reset initiation, factors, HIBP or session adapter composition.
type resetNativePhase struct {
	replacementNativePhase
	service    capability.Service
	failCommit bool
}

func (*resetNativePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{credentialResetOperation()}
}
func (*resetNativePhase) CredentialReset(c identity.Command) (CredentialResetIntent, error) {
	s, ok := c.PasswordResetFeature()
	if !ok {
		return CredentialResetIntent{}, invalidCredentialReset()
	}
	return decodeCredentialReset(s)
}
func (p *resetNativePhase) ValidateFeatureCommand(c identity.Command, plan CommandPlan) error {
	s, ok := c.PasswordResetFeature()
	if !ok || s.Operation != credentialResetOperation() || len(s.Fields) != 9 || plan.Capability == nil {
		return invalidCredentialReset()
	}
	return nil
}
func (p *resetNativePhase) checkProof(ctx context.Context, c identity.Command) error {
	s, _ := c.PasswordResetFeature()
	_, proof, ok := c.PasswordResetCustody()
	if !ok {
		return invalidCredentialReset()
	}
	g, err := p.service.Verify(ctx, proof, "identity.password.reset-complete", "identity")
	if err != nil {
		return identity.ForbiddenError{}
	}
	payload := g.Payload()
	if payload.Tenant != string(s.Binding.TenantID) || payload.Subject != string(s.Binding.UserID) || payload.Resource != "identity.password/"+s.Binding.RecordID {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *resetNativePhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := p.checkProof(ctx, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return p.replacementNativePhase.ApplyFeature(ctx, w, c)
}
func (p *resetNativePhase) CheckFeatureCommit(ctx context.Context, w Work, c identity.Command) error {
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return err
	}
	if p.failCommit {
		return identity.UnavailableError{}
	}
	return p.checkProof(ctx, c)
}

type resetOutboxPhase struct{ replacementOutboxPhase }

func (p *resetOutboxPhase) PersistCredentialReset(ctx context.Context, w Work) error {
	return p.PersistCredentialReplacement(ctx, w)
}

// The registered pointer, not its embedded fixture, owns recovery authority.
func (p *emailVerificationCapabilityPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	p.retainedEvidence = w
	b, err := w.CapabilityBinding(p)
	if err != nil {
		return RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.capability_recovery_fixture WHERE tenant_id=$1 AND purpose=$2 AND capability_id=$3 AND state='reserved' AND command_id=$4 AND fingerprint=$5 AND generation=$6::numeric AND expiry=$7)`, string(b.Command.TenantID), string(b.Plan.Purpose), b.Plan.CapabilityID, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.PreviousGeneration, 10), b.Plan.ExpiresAt)
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var exact bool
	if !rows.Next() || rows.Scan(&exact) != nil || rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if !exact {
		return RecoveryUnknown, nil
	}
	return RecoveryNotCommitted, nil
}

func testCredentialReset(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE IF NOT EXISTS public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS public.identity_test_replacement_native(tenant_id text,user_id text,credential_id text,version numeric NOT NULL,command_id text UNIQUE,PRIMARY KEY(tenant_id,user_id,credential_id));
CREATE TABLE IF NOT EXISTS public.identity_test_replacement_epochs(command_id text PRIMARY KEY,user_before numeric,user_after numeric,epoch_before numeric,epoch_after numeric,record_before numeric,record_after numeric);
CREATE TABLE IF NOT EXISTS identity.capability_recovery_fixture(tenant_id text NOT NULL,purpose text NOT NULL,capability_id text PRIMARY KEY,expiry timestamptz NOT NULL,state text NOT NULL,command_id text,fingerprint bytea,generation numeric)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "competing-commands", "disabled-recovery", "stale-user", "stale-epoch", "stale-record", "enabled-mismatch", "banned", "expired-credential", "native-failure", "receipt-failure", "audit-failure", "outbox-failure", "finalize-failure", "commit-admission-failure", "counter-denied", "recovery-negative", "recovery-retained"} {
		t.Run(mode, func(t *testing.T) {
			command, plan, intent := resetPlanFixture(t)
			s, _ := command.PasswordResetFeature()
			b := s.Binding
			var err error
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			id, err := identity.NewSubjectID()
			if err != nil {
				t.Fatal(err)
			}
			b.UserID = identity.UserID(id)
			intent.Replacement.Credential.UserID = b.UserID
			intent.ExpectedEnabled = mode != "disabled-recovery"
			u, a, r := uint64(11), uint64(13), uint64(7)
			enabled, status := intent.ExpectedEnabled, "active"
			var expiry *time.Time
			switch mode {
			case "stale-user":
				u++
			case "stale-epoch":
				a++
			case "stale-record":
				r++
			case "enabled-mismatch":
				enabled = !enabled
			case "banned":
				status = "banned"
			case "expired-credential":
				v := time.Now().UTC().Add(-time.Hour)
				expiry = &v
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,credential_version,identifier_version,authority_version) VALUES($1,$2,$3,$4::numeric,$5::numeric,17,19)`, string(b.TenantID), string(b.UserID), status, strconv.FormatUint(u, 10), strconv.FormatUint(a, 10)); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled,expires_at) VALUES($1,$2,$3,1,'identity/password',$4::numeric,$5,$6)`, string(b.TenantID), string(b.UserID), b.RecordID, strconv.FormatUint(r, 10), enabled, expiry); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.identity_test_replacement_native VALUES($1,$2,$3,7,NULL)`, string(b.TenantID), string(b.UserID), b.RecordID); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			proofExpiry := now.Add(time.Minute)
			if mode == "commit" {
				proofExpiry = now.Add(3 * time.Second)
			}
			signer, err := capability.NewHMACSHA256Signer("reset-fixture", bytes.Repeat([]byte{1}, 32))
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := capability.NewHMACSHA256Verifier(bytes.Repeat([]byte{1}, 32))
			if err != nil {
				t.Fatal(err)
			}
			keys, err := capability.NewKeySet([]capability.Key{{ID: "reset-fixture", Verifier: verifier}})
			if err != nil {
				t.Fatal(err)
			}
			service, err := capability.NewService(capability.ServiceConfig{Signer: signer, Resolver: keys, Clock: time.Now, Limits: capability.DefaultLimits()})
			if err != nil {
				t.Fatal(err)
			}
			payload := capability.Payload{Version: 1, Issuer: "https://issuer.example", Audiences: []string{"identity"}, Subject: string(b.UserID), Resource: "identity.password/" + b.RecordID, Operation: b.OperationID, IssuedAt: now, NotBefore: now, ExpiresAt: proofExpiry, ID: "reset-" + string(id), Tenant: string(b.TenantID), MaxUses: 1}
			wire, err := capability.Issue(ctx, payload, signer, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			proof, err := capability.ParseProof(wire, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			grant, err := service.Verify(ctx, proof, "identity.password.reset-complete", "identity")
			if err != nil {
				t.Fatal(err)
			}
			s.Binding = b
			s.Fields, err = CredentialResetFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			command = passwordResetCodecCommand(t, s, "synthetic", proof)
			plan.Capability.CapabilityID, plan.Capability.ExpiresAt, plan.Capability.ProofFingerprint = payload.ID, proofExpiry, grant.EnvelopeDigest()
			native := &resetNativePhase{service: service, failCommit: mode == "commit-admission-failure"}
			native.fail, native.wrongReceipt = mode == "native-failure", mode == "receipt-failure"
			auditing, outbox, oneUse, counters := &recoveryAuditPhase{}, &resetOutboxPhase{}, &emailVerificationCapabilityPhase{failFinalize: mode == "finalize-failure"}, &emailVerificationCounterPhase{deny: mode == "counter-denied"}
			auditing.fail, outbox.fail = mode == "audit-failure", mode == "outbox-failure"
			registry, err := NewContributorRegistry([]Contributor{repo, auditing, outbox, native, counters, oneUse})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			plan.Contributors = registry.Descriptors()
			coordinator.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			})}
			coordinator.commandRead = coordinator.readCommand
			seed, err := securityMutationAudit(ctx, b, 7, 8, now, "committed", "identity.password.reset-complete", "credential", b.RecordID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, s.Operation, "credential", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err = coordinator.PrepareCommandPlan(b, command, plan)
			if err != nil {
				t.Fatal("reset cannot prepare", err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.capability_recovery_fixture VALUES($1,$2,$3,$4,'issued',NULL,NULL,NULL)`, string(b.TenantID), b.OperationID, payload.ID, proofExpiry); err != nil {
				t.Fatal(err)
			}
			var reservation Reservation
			if mode == "competing-commands" {
				other := s
				other.Binding.CommandID, err = identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				otherCommand := passwordResetCodecCommand(t, other, "synthetic", proof)
				otherPlan := resetAlternatePlan(t, ctx, coordinator, other, otherCommand, plan, now)
				type attempt struct {
					binding     identity.CommandBinding
					command     identity.Command
					plan        CommandPlan
					reservation Reservation
					err         error
				}
				start, results := make(chan struct{}), make(chan attempt, 2)
				for _, candidate := range []attempt{{binding: b, command: command, plan: plan}, {binding: other.Binding, command: otherCommand, plan: otherPlan}} {
					go func(a attempt) {
						<-start
						a.reservation, _, a.err = coordinator.ReserveCommand(ctx, a.binding, a.command, a.plan)
						results <- a
					}(candidate)
				}
				close(start)
				wins := 0
				for range 2 {
					a := <-results // both bounded calls finish before the fixture exits
					if a.err == nil {
						wins++
						b, command, plan, reservation = a.binding, a.command, a.plan, a.reservation
					} else {
						var conflict identity.ConflictError
						if !errors.As(a.err, &conflict) {
							t.Errorf("competing reservation did not fail by conflict: %T", a.err)
						}
					}
				}
				if wins != 1 {
					t.Fatal("one proof admitted competing reset commands", wins)
				}
				s.Binding = b
			} else {
				reservation, _, err = coordinator.ReserveCommand(ctx, b, command, plan)
			}
			if mode == "recovery-negative" || mode == "recovery-retained" {
				if err != nil {
					t.Fatal("recovery reservation", err)
				}
				key, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, key); err != nil {
					t.Fatal(err)
				}
				if mode == "recovery-retained" {
					if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_replacements VALUES($1,$2,$3,$4,$5,$6,11,12,13,14,7,8)`, string(b.CommandID), key, string(b.TenantID), string(b.UserID), b.RecordID, b.OperationID); err != nil {
						t.Fatal(err)
					}
				}
				q, caller := queryInputs(b)
				observed, err := coordinator.RecoverCommand(ctx, q, caller)
				var unavailable identity.UnavailableError
				want := identity.CommitOutcomeNotCommitted
				if mode == "recovery-retained" {
					want = identity.CommitOutcomeInProgress
				}
				if !errors.As(err, &unavailable) || observed.Outcome != want {
					t.Fatal("unsafe reset recovery conclusion", observed.Outcome, err)
				}
				return
			}
			if mode != "counter-denied" {
				if err != nil {
					t.Fatal("reset cannot reserve", err)
				}
				work, e := coordinator.Begin(ctx, reservation)
				if e != nil {
					t.Fatal(e)
				}
				defer coordinator.Abort(work, identity.UnavailableError{})
				result, e := coordinator.ApplyFeature(ctx, work, command)
				if e == nil {
					result, e = coordinator.Commit(work, result)
				} else {
					_, _ = coordinator.Abort(work, e)
				}
				success := mode == "commit" || mode == "disabled-recovery" || mode == "competing-commands"
				if success && (e != nil || result.Outcome != identity.CommitOutcomeCommitted) {
					t.Fatal("reset did not commit", e)
				}
				if !success && e == nil {
					t.Fatal("unsafe reset committed")
				}
				if mode == "commit" {
					timer := time.NewTimer(time.Until(proofExpiry))
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-ctx.Done():
						t.Fatal("expiry wait budget")
					}
					_, replay, e := coordinator.ReserveCommand(ctx, b, command, plan)
					if e != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.Feature == nil || *replay.Feature != *result.Feature {
						t.Fatal("expired matching replay changed original outcome", e)
					}
					other := s
					other.Binding.CommandID, _ = identity.NewCommandID()
					otherCommand := passwordResetCodecCommand(t, other, "synthetic", proof)
					otherPlan := resetAlternatePlan(t, ctx, coordinator, other, otherCommand, plan, now)
					if _, _, e := coordinator.ReserveCommand(ctx, other.Binding, otherCommand, otherPlan); e == nil {
						t.Fatal("foreign command reused terminal capability")
					}
				}
			} else if err == nil {
				t.Fatal("counter denial admitted reset")
			}
			current, err := repo.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: b.TenantID, UserID: b.UserID, CredentialID: identity.CredentialID(b.RecordID)})
			if err != nil {
				t.Fatal(err)
			}
			wantEffects := 0
			if mode == "commit" || mode == "disabled-recovery" || mode == "competing-commands" {
				u++
				a++
				r++
				enabled = true
				wantEffects = 1
			}
			if current.User.Version != u || current.AuthorityVersion != a || current.Credential.Version != r || current.Enabled != enabled {
				t.Fatal("reset atomic versions/enablement violated")
			}
			var nativeVersion string
			if err := pool.Raw().QueryRow(ctx, `SELECT version::text FROM public.identity_test_replacement_native WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, string(b.TenantID), string(b.UserID), b.RecordID).Scan(&nativeVersion); err != nil || nativeVersion != strconv.Itoa(7+wantEffects) {
				t.Fatal("native verifier mutation escaped outcome", err)
			}
			var effects, audits, lifecycle, epochs int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.credential_replacements WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_replacement_epochs WHERE command_id=$1)`, string(b.CommandID)).Scan(&effects, &audits, &lifecycle, &epochs); err != nil || effects != wantEffects || lifecycle != wantEffects || epochs != wantEffects {
				t.Fatal("reset effects escaped shared outcome", err)
			}
			if wantEffects == 1 && audits != 1 {
				t.Fatal("committed reset audit missing")
			}
			var capState string
			if err := pool.Raw().QueryRow(ctx, `SELECT state FROM identity.capability_recovery_fixture WHERE capability_id=$1`, payload.ID).Scan(&capState); err != nil {
				t.Fatal(err)
			}
			if wantEffects == 1 && capState != "finalized" || wantEffects == 0 && capState == "finalized" || mode == "counter-denied" && capState != "issued" {
				t.Fatal("capability finalization escaped reset outcome")
			}
			key, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			var journalState string
			if err := pool.Raw().QueryRow(ctx, `SELECT state FROM identity.commands WHERE command_id=$1`, key).Scan(&journalState); err != nil {
				t.Fatal(err)
			}
			if wantEffects == 1 && journalState != "committed" || wantEffects == 0 && journalState == "committed" {
				t.Fatal("journal contradicts reset effects")
			}
		})
	}
}

func resetAlternatePlan(t *testing.T, ctx context.Context, c *Coordinator, s identity.FeatureCommandSpec, command identity.Command, plan CommandPlan, now time.Time) CommandPlan {
	t.Helper()
	plan.Audits = append([]AuditPlan(nil), plan.Audits...)
	seed, err := securityMutationAudit(ctx, s.Binding, 7, 8, now, "committed", "identity.password.reset-complete", "credential", s.Binding.RecordID, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(s.Binding, s.Operation, "credential", seed)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = c.PrepareCommandPlan(s.Binding, command, plan)
	if err != nil {
		t.Fatal("alternate command must have a valid independent plan", err)
	}
	return plan
}
