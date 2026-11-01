//go:build integration

package postgres

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

// These SQL owner fixtures exercise the kernel's protected transaction. They
// are not an OIDC provider/session implementation or the social consumer journey.
type accountLinkSQLProvider struct {
	accountLinkOwnerProbe
	command    identity.Command
	capability CapabilityPlan
	fail       string
	phase      string
	checkError string
	counter    *accountLinkCounterProbe
}

func (p *accountLinkSQLProvider) RecoverParticipant(ctx context.Context, h RecoveryWork) (RecoveryStatus, error) {
	if p.fail == "pending-unknown" {
		return RecoveryUnknown, nil
	}
	return recoveryTestEvidence(ctx, h, "public.link_provider_effect")
}

func (p *accountLinkSQLProvider) PrepareAccountLink(_ context.Context, command identity.Command) (identity.Command, CommandCounterPlan, CapabilityPlan, error) {
	c, err := identity.NewAccountLinkCounterCommand(command, identity.AccountLinkCounterContext{Network: "192.0.2.15", PreparedAt: p.commandTime(), KeyVersions: []uint32{7}})
	return c, CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{4}}, p.capability, err
}

func (p *accountLinkSQLProvider) commandTime() time.Time {
	return p.capability.ExpiresAt.Add(-4 * time.Minute)
}

func (p *accountLinkSQLProvider) CheckAccountLink(ctx context.Context, h AccountLinkWork) (err error) {
	defer func() { p.checkError = fmt.Sprintf("%T", err) }()
	p.phase = "initial-check"
	spec, final, err := h.Command(p)
	if final {
		p.phase = "final-check"
	}
	if err != nil {
		return err
	}
	if !final && p.fail == "initial" || final && p.fail == "final" {
		return identity.ForbiddenError{}
	}
	epoch, err := h.CredentialAuthorityVersion(p)
	if err != nil {
		return err
	}
	wantedUser := spec.Change.ExpectedUserVersion
	if final {
		wantedUser++
	}
	rows, err := h.Query(ctx, `SELECT version::text,credential_version::text,status FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR SHARE`, string(spec.Binding.TenantID), string(spec.Binding.UserID))
	if err != nil {
		return err
	}
	defer rows.Close()
	var user, credential, status string
	if !rows.Next() {
		return identity.ForbiddenError{}
	}
	if err := rows.Scan(&user, &credential, &status); err != nil {
		return err
	}
	if rows.Next() || rows.Err() != nil || user != strconv.FormatUint(wantedUser, 10) || credential != strconv.FormatUint(epoch, 10) || status != "active" {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *accountLinkSQLProvider) PersistAccountLink(ctx context.Context, h AccountLinkWork) error {
	p.phase = "persist"
	s, final, err := h.Command(p)
	if err != nil || final {
		return invalidWork()
	}
	if _, err := h.Exec(ctx, `INSERT INTO public.link_provider_effect(command_id,finalized) VALUES($1,false)`, string(s.Binding.CommandID)); err != nil {
		return err
	}
	if p.fail == "persist" {
		return identity.UnavailableError{}
	}
	return nil
}

func (p *accountLinkSQLProvider) FinalizeAccountLink(ctx context.Context, h AccountLinkWork) error {
	p.phase = "finalize"
	s, final, err := h.Command(p)
	if err != nil || !final {
		return invalidWork()
	}
	n, err := h.Exec(ctx, `UPDATE public.link_provider_effect SET finalized=true WHERE command_id=$1 AND NOT finalized`, string(s.Binding.CommandID))
	if err != nil {
		return err
	}
	if n != 1 || p.fail == "finalize" {
		return identity.UnavailableError{}
	}
	if p.fail == "late-counter" {
		now, err := h.DatabaseTime(ctx)
		if err != nil {
			return err
		}
		delay := p.counter.expiresAt.Sub(now) + 10*time.Millisecond
		if delay > 0 {
			if _, err := h.Exec(ctx, `SELECT pg_sleep($1)`, delay.Seconds()); err != nil {
				return err
			}
		}
	}
	return nil
}

type accountLinkSQLAudit struct{ recoveryAuditPhase }

func (p *accountLinkSQLAudit) PersistAudits(ctx context.Context, w Work) error {
	records, err := w.StagedAudits()
	if err != nil {
		return err
	}
	if err := p.recoveryAuditPhase.PersistAudits(ctx, w); err != nil {
		return err
	}
	for _, entry := range records {
		r := entry.Record
		if _, err := w.Exec(ctx, `UPDATE public.identity_test_audits SET no_change=$2,outcome=$3,reason=$4 WHERE event_id=$1`, r.ID(), r.Changes().NoChange(), int16(r.Outcome()), r.ReasonCode()); err != nil {
			return err
		}
	}
	return nil
}

type accountLinkSQLCapability struct{ capabilityExecutionProbe }

func (p *accountLinkSQLCapability) RecoverParticipant(ctx context.Context, h RecoveryWork) (RecoveryStatus, error) {
	b, err := h.CapabilityBinding(p)
	if err != nil {
		return RecoveryUnknown, err
	}
	rows, err := h.Query(ctx, `SELECT state FROM public.link_capability_effect WHERE command_id=$1`, string(b.Command.CommandID))
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var state string
	if !rows.Next() || rows.Scan(&state) != nil || rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if state == "reserved" {
		return RecoveryNotCommitted, nil
	}
	return RecoveryUnknown, nil
}

func (p *accountLinkSQLCapability) ReserveCapability(ctx context.Context, h CapabilityReservationWork) error {
	b, err := h.Binding(p)
	if err != nil {
		return err
	}
	_, err = h.Exec(ctx, `INSERT INTO public.link_capability_effect(command_id,state) VALUES($1,'reserved')`, string(b.Command.CommandID))
	return err
}
func (p *accountLinkSQLCapability) ApplyCapability(ctx context.Context, h CapabilityApplyWork) error {
	b, err := h.Binding(p)
	if err != nil {
		return err
	}
	n, err := h.Exec(ctx, `UPDATE public.link_capability_effect SET state='applied' WHERE command_id=$1 AND state='reserved'`, string(b.Command.CommandID))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}
func (p *accountLinkSQLCapability) FinalizeCapability(ctx context.Context, h CapabilityFinalizeWork) error {
	b, err := h.Binding(p)
	if err != nil {
		return err
	}
	n, err := h.Exec(ctx, `UPDATE public.link_capability_effect SET state='finalized' WHERE command_id=$1 AND state='applied'`, string(b.Command.CommandID))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}
func (p *accountLinkSQLCapability) ReleaseCapability(ctx context.Context, h CapabilityReleaseWork) error {
	b, err := h.Binding(p)
	if err != nil {
		return err
	}
	n, err := h.Exec(ctx, `UPDATE public.link_capability_effect SET state='released' WHERE command_id=$1 AND state='reserved'`, string(b.Command.CommandID))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func liveAccountLinkOwnerCommand(t *testing.T) identity.Command {
	t.Helper()
	base := recordLink(t, identity.AccountLinkExplicit, func(c *identity.AccountLinkCommand) {
		c.Binding.UserID, c.Binding.ActorID = "owner", "owner"
		var err error
		c.Binding.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		c.Change.Account.UserID = "owner"
		c.Change.Method.Credential.UserID = "owner"
		c.Change.Method.ExpiresAt = time.Time{}
	}, nil, "proof-key")
	s, _ := base.LinkAccount()
	s.Proof = capability.Grant{}
	now := time.Now().UTC().Truncate(time.Second)
	payload, err := identity.BuildAccountLinkProofPayload(identity.AccountLinkProofSpec{Command: s, Issuer: "https://identity.example.test", Audience: "backend", ID: string(s.Binding.CommandID), IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(4 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{1}, 32)
	signer, _ := capability.NewHMACSHA256Signer("proof-key", key)
	verifier, _ := capability.NewHMACSHA256Verifier(key)
	keys, _ := capability.NewKeySet([]capability.Key{{Issuer: payload.Issuer, ID: "proof-key", Verifier: verifier}})
	token, err := capability.Issue(t.Context(), payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	s.Proof, err = capability.Verify(t.Context(), token, keys, capability.VerifyOptions{Issuer: payload.Issuer, Now: now, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewAccountLinkCommand(s)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func TestAccountLinkOwnerAtomicExecution(t *testing.T) {
	for _, mode := range []string{"success", "initial", "persist", "final", "finalize", "outbox", "audit", "counter-denied", "pending-negative", "pending-unknown", "late-counter"} {
		t.Run(mode, func(t *testing.T) {
			ctx, pool, repo := newAccountAuthorityStore(t)
			if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE,no_change boolean,outcome smallint,reason text);
CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE public.link_provider_effect(command_id text PRIMARY KEY,finalized boolean NOT NULL);
CREATE TABLE public.link_capability_effect(command_id text PRIMARY KEY,state text NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			command := liveAccountLinkOwnerCommand(t)
			spec, _ := command.LinkAccount()
			proof := spec.Proof.Payload()
			provider := &accountLinkSQLProvider{command: command, fail: mode, capability: CapabilityPlan{CapabilityID: proof.ID, Purpose: "identity.account.link-token", ReplayDigest: [32]byte{3}, ReplayKeyVersion: 1, ProofFingerprint: spec.Proof.EnvelopeDigest(), ExpiresAt: proof.ExpiresAt, MaxUses: 1}}
			audits, lifecycle := &accountLinkSQLAudit{}, &recoveryLifecyclePhase{}
			audits.fail = mode == "audit"
			lifecycle.fail = mode == "outbox"
			cap := &accountLinkSQLCapability{}
			counter := &accountLinkCounterProbe{deny: mode == "counter-denied"}
			if mode == "late-counter" {
				counter.evidenceTTL = 2 * time.Second
			}
			provider.counter = counter
			registry, err := NewContributorRegistry([]Contributor{repo, audits, lifecycle, cap, counter, provider})
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 5 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			owner, err := NewAccountLinkUnitOfWork(c, repo, AccountLinkUnitOfWorkConfig{RetentionPolicyVersion: 1})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "pending-negative" || mode == "pending-unknown" {
				prepared, counters, capPlan, e := provider.PrepareAccountLink(ctx, command)
				if e != nil {
					t.Fatal(e)
				}
				_, _, p := accountLinkOwnerPlanFixture(t)
				p.Contributors, p.CommandCounters, p.Capability = registry.Descriptors(), &counters, &capPlan
				seed, e := kernelMutationAudit(ctx, spec.Binding, 0, provider.commandTime(), "committed")
				if e != nil {
					t.Fatal(e)
				}
				p.Audits[0].BindingDigest, e = AuditBindingDigest(spec.Binding, seed)
				if e != nil {
					t.Fatal(e)
				}
				p, e = c.PrepareCommandPlan(spec.Binding, prepared, p)
				if e != nil {
					t.Fatal(e)
				}
				r, observed, e := c.ReserveCommand(ctx, spec.Binding, prepared, p)
				if e != nil || r.state == nil || observed.Outcome != identity.CommitOutcomeInProgress {
					t.Fatal("pending setup", e)
				}
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second'`); e != nil {
					t.Fatal(e)
				}
				got, e := owner.Recover(ctx, creationRecoveryQuery(spec.Binding))
				var capState string
				if readErr := pool.Raw().QueryRow(ctx, `SELECT state FROM public.link_capability_effect LIMIT 1`).Scan(&capState); readErr != nil {
					t.Fatal(readErr)
				}
				if mode == "pending-negative" {
					if got.Outcome != identity.CommitOutcomeNotCommitted || capState != "released" {
						t.Fatal("unanimous negative recovery did not close original link", got.Outcome, capState, e)
					}
					if _, e := c.Begin(ctx, r); e == nil {
						t.Fatal("old link owner revived after recovery")
					}
				} else if got.Outcome != identity.CommitOutcomeInProgress || capState != "reserved" {
					t.Fatal("uncertain provider outcome released original capability", got.Outcome, capState, e)
				}
				return
			}
			result, err := owner.Execute(ctx, command)
			state, readErr := repo.GetAccountLinkState(ctx, identity.AccountLinkQuery{Account: spec.Change.Account, Mode: spec.Change.Mode})
			if readErr != nil {
				t.Fatal(readErr)
			}
			var providerCount, effects int
			var capabilityState string
			if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.link_provider_effect),(SELECT count(*) FROM public.identity_test_lifecycle),coalesce((SELECT state FROM public.link_capability_effect LIMIT 1),'none')`).Scan(&providerCount, &effects, &capabilityState); e != nil {
				t.Fatal(e)
			}
			if mode != "success" {
				if result.Outcome == identity.CommitOutcomeCommitted || result.Outcome != identity.CommitOutcomeNotCommitted && err == nil || state.Access.User.Version != 1 || state.CredentialVersion != 1 || state.RecordVersion != 0 || providerCount != 0 || effects != 0 || capabilityState == "applied" || capabilityState == "finalized" {
					t.Fatal("failed phase leaked protected effects", mode, err)
				}
				if mode == "counter-denied" {
					var count int
					if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_test_audits`).Scan(&count); e != nil || count != 1 || result.Outcome != identity.CommitOutcomeNotCommitted || capabilityState != "none" {
						t.Fatal("counter denial lost required durable audit/outcome", count, result.Outcome, err, e)
					}
				}
				var auditCount int
				if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_test_audits`).Scan(&auditCount); e != nil {
					t.Fatal(e)
				}
				if mode == "audit" {
					if result.Outcome != identity.CommitOutcomeUnknown || err == nil || capabilityState != "reserved" || auditCount != 0 {
						t.Fatal("audit failure invented known rollback", result.Outcome, capabilityState, auditCount, err)
					}
				} else {
					wantCapability := "released"
					if mode == "counter-denied" {
						wantCapability = "none"
					}
					if result.Outcome != identity.CommitOutcomeNotCommitted || capabilityState != wantCapability || auditCount != 1 {
						t.Fatal("known rollback stranded custody or lost its receipt/audit", mode, result.Outcome, capabilityState, auditCount, err)
					}
					var noChange bool
					var outcome int16
					var reason string
					if e := pool.Raw().QueryRow(ctx, `SELECT no_change,outcome,reason FROM public.identity_test_audits`).Scan(&noChange, &outcome, &reason); e != nil {
						t.Fatal(e)
					}
					wantOutcome, wantReason := audit.OutcomeFailed, "provider_unavailable"
					if mode == "initial" || mode == "final" || mode == "counter-denied" || mode == "late-counter" {
						wantOutcome, wantReason = audit.OutcomeDenied, "not_authorized"
					}
					if !noChange || outcome != int16(wantOutcome) || reason != wantReason {
						t.Fatal("rollback audit does not describe the denial/failure", noChange, outcome, reason)
					}
					recovered, e := owner.Recover(ctx, creationRecoveryQuery(spec.Binding))
					if e != nil || !reflect.DeepEqual(recovered, result) {
						t.Fatal("rollback recovery changed original classification", mode, e)
					}
				}
				if mode == "late-counter" && (counter.checkedAt.Before(counter.expiresAt) || !proof.ExpiresAt.After(counter.checkedAt)) {
					t.Fatal("test did not cross original counter expiry with a live link proof")
				}
				wantedPhase := map[string]string{"initial": "initial-check", "persist": "persist", "final": "final-check", "finalize": "finalize", "outbox": "persist", "audit": "persist", "late-counter": "finalize"}[mode]
				if wantedPhase != "" && provider.phase != wantedPhase {
					t.Fatal("test never reached its selected failure", mode, provider.phase, provider.checkError)
				}
				return
			}
			if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Link == nil || result.User.Version != 2 || result.Link.CredentialVersion != 2 || state.RecordVersion != 1 || state.SocialLinkVersion != 2 || state.CredentialVersion != 2 || providerCount != 1 || effects != 1 || capabilityState != "finalized" {
				t.Fatal("complete native link failed", "outcome", result.Outcome, "user", state.Access.User.Version, "record", state.RecordVersion, "social", state.SocialLinkVersion, "credential", state.CredentialVersion, "provider", providerCount, "effects", effects, "capability", capabilityState, "phase", provider.phase, "check", provider.checkError, err)
			}
			query := creationRecoveryQuery(spec.Binding)
			got, err := owner.Recover(ctx, query)
			if err != nil || !reflect.DeepEqual(got, result) {
				t.Fatal("historical link recovery changed result", err)
			}
			again, err := owner.Execute(ctx, command)
			if err != nil || !reflect.DeepEqual(again, result) {
				t.Fatal("exact link replay changed result", err)
			}
		})
	}
}
