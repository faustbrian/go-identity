//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// Kernel-owner composition only: these declared participants provide no real
// target-password, guest-session, capability-signature or risk authority. The
// native anonymous service must independently prove those consumed contracts.
type upgradeKernelCounter struct{ commandCounterProbe }

func (*upgradeKernelCounter) CheckCommandCounters(context.Context, CommandCounterAdmissionWork) error {
	return nil
}

type upgradeKernelCapability struct{ capabilityExecutionProbe }

func (p *upgradeKernelCapability) ReserveCapability(_ context.Context, w CapabilityReservationWork) error {
	_, err := w.Binding(p)
	return err
}
func (p *upgradeKernelCapability) RebindCapability(_ context.Context, w CapabilityReservationWork) error {
	_, err := w.Binding(p)
	return err
}
func (p *upgradeKernelCapability) ApplyCapability(_ context.Context, w CapabilityApplyWork) error {
	_, err := w.Binding(p)
	return err
}
func (p *upgradeKernelCapability) FinalizeCapability(_ context.Context, w CapabilityFinalizeWork) error {
	_, err := w.Binding(p)
	return err
}

type anonymousUpgradeDisposalPhase struct {
	*anonymousUpgradeProbe
	domain  *AnonymousDisposalDomain
	intent  AnonymousDisposalIntent
	mode    string
	applied bool
}

func (p *anonymousUpgradeDisposalPhase) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	if p.mode != "missing-kernel" {
		if p.mode == "lost-consumption" {
			w.state.anonymousUpgradeConsumed = false
		}
		actual := command
		if p.mode == "reconstructed" {
			s, _ := command.Feature()
			actual, _ = identity.NewFeatureCommand(s)
		}
		u, err := p.domain.ApplyUpgrade(ctx, w, p, actual, p.intent)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		got, err := w.AnonymousUpgradeDisposal(p)
		if err != nil || got != u || string(got.ID) == string(w.state.binding.UserID) {
			return identity.FeatureReceipt{}, invalidAnonymousDisposal()
		}
		if _, err := w.AnonymousDisposal(p); err == nil {
			return identity.FeatureReceipt{}, invalidWork()
		}
		p.applied = true
		if p.mode == "duplicate" {
			_, _ = p.domain.ApplyUpgrade(ctx, w, p, actual, p.intent)
		}
	}
	if p.mode == "native-failure" {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	_, err := w.Exec(ctx, `INSERT INTO public.identity_test_anonymous_effect(command_id,user_id) VALUES($1,$2)`, string(w.state.binding.CommandID), w.state.binding.RecordID)
	return identity.FeatureReceipt{Operation: anonymousUpgradeOperation(), BeforeVersion: 1, AfterVersion: 2}, err
}

func (p *anonymousUpgradeDisposalPhase) CheckFeatureCommit(ctx context.Context, w Work, c identity.Command) error {
	if p.mode == "final-failure" {
		return identity.ForbiddenError{}
	}
	return p.domain.CheckUpgrade(ctx, w, p, c, p.intent)
}
func (*anonymousUpgradeDisposalPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "public.identity_test_anonymous_effect")
}

func TestAnonymousUpgradeDisposalPostgresPreservesPermanentTarget(t *testing.T) {
	ctx, pool, repository := anonymousKernelDatabase(t)
	// A real created guest and existing permanent user precede the forward
	// migration. No original anonymous creation/disposal migration is rewritten.
	first := createAnonymousForDisposal(t, ctx, pool, repository)
	const target = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',7)`, string(first.User.TenantID), target); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, anonymousUpgradeDisposalSQL); err != nil {
		t.Fatal("populated upgrade disposal suffix", err)
	}
	domain, err := NewAnonymousDisposalDomain(repository)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "reconstructed", "missing-kernel", "lost-consumption", "duplicate", "native-failure", "audit-failure", "outbox-failure", "final-failure", "changed-hold", "changed-epoch"} {
		t.Run(mode, func(t *testing.T) {
			a := first
			if mode != "commit" {
				a = createAnonymousForDisposal(t, ctx, pool, repository)
			}
			snapshot, err := repository.GetAnonymousDisposal(ctx, identity.UserStatusQuery{TenantID: a.User.TenantID, UserID: a.User.ID})
			if err != nil {
				t.Fatal(err)
			}
			intent := AnonymousDisposalIntent{Snapshot: snapshot, Action: AnonymousDisposeDelete, RetentionPolicyVersion: 1}
			fields, err := AnonymousDisposalFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			b, plan := anonymousUpgradePlanFixture(t)
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			b.TenantID, b.UserID, b.ActorID, b.ActorKind, b.RecordID = a.User.TenantID, target, target, authorization.SubjectUser, string(a.User.ID)
			command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: plan.Feature.Operation, Fields: fields})
			p := &anonymousUpgradeDisposalPhase{anonymousUpgradeProbe: &anonymousUpgradeProbe{scopeFeatureParticipant: scopeFeatureParticipant{operations: []identity.FeatureOperation{plan.Feature.Operation}}, expected: command, proof: *plan.Capability}, domain: domain, intent: intent, mode: mode}
			audits := &anonymousCreationAuditPhase{recoveryAuditPhase: recoveryAuditPhase{domainAuditPhase: domainAuditPhase{fail: mode == "audit-failure"}}}
			outbox := &recoveryLifecyclePhase{domainLifecyclePhase: domainLifecyclePhase{fail: mode == "outbox-failure"}}
			registry, err := NewContributorRegistry([]Contributor{repository, audits, outbox, p, &upgradeKernelCounter{}, &upgradeKernelCapability{}})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			plan.Contributors = registry.Descriptors()
			seed, err := securityMutationAudit(ctx, b, 1, 2, time.Now().UTC().Truncate(time.Microsecond), "committed", plan.Audits[0].EventType, "anonymous", b.RecordID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, plan.Feature.Operation, "anonymous", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err = coordinator.PrepareCommandPlan(b, command, plan)
			if err != nil {
				t.Fatal("upgrade plan", err)
			}
			if mode == "changed-hold" {
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.users SET legal_hold=true,legal_hold_version=2 WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), b.RecordID)
			} else if mode == "changed-epoch" {
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.users SET authority_version=2 WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), b.RecordID)
			}
			if err != nil {
				t.Fatal(err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal("reserve", err)
			}
			w, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal("begin", err)
			}
			result, applyErr := coordinator.ApplyFeature(ctx, w, command)
			if applyErr != nil {
				result, _ = coordinator.Abort(w, applyErr)
			} else {
				result, err = coordinator.Commit(w, result)
			}
			committed := mode == "commit"
			if committed && (err != nil || applyErr != nil || result.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("upgrade guest disposal did not commit", err, applyErr, result.Outcome)
			}
			if !committed && result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("invalid disposal committed")
			}
			var status, version, targetStatus, targetVersion, targetEpoch string
			var attrs, effects, native, auditCount, outboxCount int
			if err := pool.Raw().QueryRow(ctx, `SELECT u.status,u.version::text,(SELECT count(*) FROM identity.user_attributes WHERE tenant_id=u.tenant_id AND user_id=u.user_id),(SELECT count(*) FROM identity.anonymous_disposals WHERE tenant_id=u.tenant_id AND user_id=u.user_id),(SELECT count(*) FROM public.identity_test_anonymous_effect WHERE command_id=$3),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$3 AND succeeded),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$3) FROM identity.users u WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), b.RecordID, string(b.CommandID)).Scan(&status, &version, &attrs, &effects, &native, &auditCount, &outboxCount); err != nil {
				t.Fatal(err)
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT status,version::text,authority_version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), target).Scan(&targetStatus, &targetVersion, &targetEpoch); err != nil {
				t.Fatal(err)
			}
			if targetStatus != "active" || targetVersion != "7" || targetEpoch != "1" {
				t.Fatal("upgrade disposed or changed permanent target")
			}
			if committed {
				if status != "deleted" || version != "2" || attrs != 0 || effects != 1 || native != 1 || auditCount != 1 || outboxCount != 1 {
					t.Fatal("guest transition lost atomicity", status, version, attrs, effects, native, auditCount, outboxCount)
				}
				_, receipt, err := coordinator.ReserveCommand(ctx, b, command, plan)
				if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("original upgrade replay lost", err)
				}
			} else if status != "active" || version != "1" || attrs != 1 || effects != 0 || native != 0 || auditCount != 0 || outboxCount != 0 {
				t.Fatal("failed upgrade escaped rollback", status, version, attrs, effects, native, auditCount, outboxCount)
			}
			if (mode == "outbox-failure" || mode == "final-failure") && (!p.applied || !audits.successAttempted) {
				t.Fatal("late rollback did not reach kernel write and audit")
			}
		})
	}
}
