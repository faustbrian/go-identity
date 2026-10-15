//go:build integration

package mfapostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	password "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
	outbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// Policy/browser admission are labeled fixture seams. The encrypted factor,
// actual code verification, child, protected transition and audit/lifecycle
// transaction are real; this deliberately makes no session/login claim.
type totpCompletionPhase struct {
	totpAttemptPhase
	plan       kernel.CommandPlan
	primary    identity.CommandID
	denyCommit bool
	completed  LockedTOTPCompletion
	checkpoint string
}

func (p *totpCompletionPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	p.checkpoint = "apply"
	p.calls++
	locked, err := LockTOTPCompletion(ctx, w, p, c, p.snapshot)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.completed = locked
	if _, _, _, err := RequireRecordedTOTPCompletion(ctx, w, p, c, locked); err == nil {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	meta, now, err := locked.VerificationState()
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	code, ok := c.OneTimeCode()
	if !ok {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	step, err := p.verifier.Verify(ctx, p.secret, code, meta.Profile, []byte("fixture/native-completion/key-v1"), now, meta.Replay)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := RecordTOTPCompletion(ctx, w, p, locked, step); err != nil {
		return identity.FeatureReceipt{}, err
	}
	scope, originalFactor, primary, err := RequireRecordedTOTPCompletion(ctx, w, p, c, locked)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if primary != p.primary || scope.Version != p.completion.ContinuationVersion || scope.ID != mfa.ContinuationID(p.completion.ID) || originalFactor != meta {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if RecordTOTPCompletion(ctx, w, p, locked, step) == nil {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	s, _ := c.Feature()
	return identity.FeatureReceipt{Operation: s.Operation}, nil
}
func (p *totpCompletionPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command || p.denyCommit {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
func (p *totpCompletionPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	p.checkpoint = "admit"
	if c != p.command {
		return identity.ForbiddenError{}
	}
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return err
	}
	return ctx.Err()
}
func (p *totpCompletionPhase) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	p.checkpoint = "generate"
	if c != p.command || generation == 0 {
		return nil, identity.ForbiddenError{}
	}
	return []byte("native-completion-fixture"), ctx.Err()
}
func (p *totpCompletionPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	p.checkpoint = "restore"
	if c != p.command || generation == 0 || string(wire) != "native-completion-fixture" {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	return c, p.plan, ctx.Err()
}

type totpCompletionAdmission struct{ p *totpCompletionPhase }

func (a totpCompletionAdmission) Check(ctx context.Context) error { return ctx.Err() }
func (a totpCompletionAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	return a.p.GenerateFeaturePreparation(ctx, a.p.command, generation)
}
func (p *totpCompletionPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.command {
		return nil, identity.ForbiddenError{}
	}
	return totpCompletionAdmission{p}, ctx.Err()
}
func (p *totpCompletionPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	return totpCompletionAdmission{p}, nil
}

func testNativeTOTPCompletion(t *testing.T, ctx context.Context, pool *database.Pool, repo *kernel.Repository, auditing *auditpg.IdentityContributor, lifecycle *outbox.Contributor, proof capability.Proof, issuer *capabilitypg.Issuer, issuerURL, factorID string, crypto *envelope.Service, primary identity.CommandID, denyCommit bool) {
	t.Helper()
	grant, _, replayVersion, err := issuer.ReadIssuanceOrigin(ctx, pool, proof, "identity.mfa.complete")
	if err != nil {
		t.Fatal("original child unavailable", err)
	}
	reader, err := NewTOTPFactorReader(pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := reader.Read(ctx, grant, issuerURL, factorID)
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := snapshot.Envelope()
	encryptionContext, _ := snapshot.EncryptionContext()
	plain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: encryptionContext})
	if err != nil {
		t.Fatal("factor decryption unavailable")
	}
	secret, err := password.NewSecret(plain)
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	verifier, err := mfa.NewTOTPVerifier([32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	continuation, err := reader.continuation.Read(ctx, grant, issuerURL)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := continuation.Bindings()
	digest, _ := continuation.ScopeDigest()
	mode := "commit"
	if denyCommit {
		mode = "late-denial"
	}
	// A terminally aborted capability reservation is deliberately not revived.
	// The owning test issues a different original challenge for each outcome.
	for _, mode := range []string{mode} {
		t.Run(mode, func(t *testing.T) {
			var now time.Time
			if err := pool.Raw().QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
				t.Fatal(err)
			}
			meta, _ := snapshot.Metadata()
			// Keep the real enrolled zero-skew policy and immutable submitted
			// code. Wait outside SQL if preparation would straddle a boundary.
			untilNext := time.Duration(int64(meta.Profile.Period) - now.UnixNano()%int64(meta.Profile.Period))
			if untilNext < 3*time.Second {
				timer := time.NewTimer(untilNext + 100*time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					t.Fatal(ctx.Err())
				case <-timer.C:
				}
				if err := pool.Raw().QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
					t.Fatal(err)
				}
			}
			var moving [8]byte
			binary.BigEndian.PutUint64(moving[:], uint64(now.Unix()/int64(meta.Profile.Period/time.Second)))
			mac := hmac.New(sha1.New, []byte("12345678901234567890"))
			_, _ = mac.Write(moving[:])
			hash := mac.Sum(nil)
			offset := hash[len(hash)-1] & 15
			code, err := auth.NewOneTimeCode(fmt.Sprintf("%08d", (binary.BigEndian.Uint32(hash[offset:offset+4])&0x7fffffff)%100000000))
			clear(hash)
			if err != nil {
				t.Fatal(err)
			}
			id, _ := identity.NewCommandID()
			b := identity.CommandBinding{CommandID: id, TenantID: s.TenantID, AnonymousFlowID: string(s.SourcePreAuthID), ActorID: "mfa-actor", ActorKind: authorization.SubjectUser, OperationID: "identity.mfa.totp-verify", SchemaID: "mfa-totp-verify", SchemaVersion: 1, PolicyID: "test-policy", PolicyVersion: 1, CorrelationID: "mfa-complete"}
			child, err := issuer.PrepareMFAConsumption(ctx, b, identity.UserID(s.SubjectID), identity.CommandID(s.ID), digest, issuerURL, proof, grant.EnvelopeDigest(), replayVersion)
			if err != nil {
				t.Fatal(err)
			}
			op := identity.FeatureOperation{Owner: "identity/mfa", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
			command, err := identity.NewFeatureOneTimeCodePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "proof-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: child.CapabilityID}}}}, code, auth.NewBearerCredential(strings.Repeat("A", 43)))
			if err != nil {
				t.Fatal(err)
			}
			completion := kernel.MFACompletionPlan{ID: identity.CommandID(s.ID), UserID: identity.UserID(s.SubjectID), ScopeDigest: digest, PolicyVersion: s.PolicyVersion, FactorVersion: s.FactorVersion, ContinuationVersion: s.Version}
			phase := &totpCompletionPhase{totpAttemptPhase: totpAttemptPhase{command: command, child: child, completion: completion, snapshot: snapshot, secret: secret, verifier: verifier}, primary: primary, denyCommit: mode == "late-denial"}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, auditing, lifecycle, phase, capabilitypg.NewParticipant()})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			record, err := builder.Build(audit.RecordInput{Action: b.OperationID, OccurredAt: now.UTC(), Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "authentication_attempt", ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(id), "retention.class": "protected", "aggregate.type": "authentication_attempt", "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0"}})
			if err != nil {
				t.Fatal(err)
			}
			auditDigest, err := kernel.FeatureAuditBindingDigest(b, op, "authentication_attempt", record)
			if err != nil {
				t.Fatal(err)
			}
			phase.plan = kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: phase.Descriptor(), Operation: op}, SubjectType: "authentication_attempt", Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: auditDigest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1"}, Capability: &child, MFACompletion: &completion}
			phase.plan, err = coordinator.PrepareFeaturePreparationPlan(command, phase.plan)
			if err != nil {
				t.Fatal("prepare native completion", err)
			}
			result, runErr := coordinator.ExecutePreparedFeature(ctx, command, phase.plan)
			var state int16
			var remaining, uses int32
			var last *string
			if err := pool.Raw().QueryRow(ctx, `SELECT c.state,c.attempts_remaining,t.last_step::text,k.uses FROM identity_mfa.continuations c JOIN identity_mfa.totp_factors t ON t.tenant_id=c.tenant_id AND t.user_id=c.user_id JOIN public.capability_identity_one_use k ON k.tenant_id=c.tenant_id AND k.capability_id=c.continuation_id WHERE c.tenant_id=$1 AND c.continuation_id=$2 AND t.factor_id=$3`, string(s.TenantID), string(s.ID), factorID).Scan(&state, &remaining, &last, &uses); err != nil {
				t.Fatal(err)
			}
			if mode == "late-denial" {
				if runErr == nil || phase.calls != 1 || state != int16(mfa.Pending) || remaining != int32(s.AttemptsRemaining) || last != nil || uses != 0 {
					t.Fatal("late denial retained child or factor completion", runErr, phase.calls, phase.checkpoint)
				}
			} else {
				if runErr != nil || result.Outcome != identity.CommitOutcomeCommitted || phase.calls != 1 || state != int16(mfa.Completed) || remaining != int32(s.AttemptsRemaining-1) || last == nil || uses != 1 {
					t.Fatal("native factor completion split transaction", runErr, phase.calls, phase.checkpoint)
				}
				replay, err := coordinator.ExecutePreparedFeature(ctx, command, phase.plan)
				if err != nil || !reflect.DeepEqual(replay, result) || phase.calls != 1 {
					t.Fatal("completion retry repeated factor use", err)
				}
			}
			if _, _, _, err := RequireRecordedTOTPCompletion(ctx, kernel.Work{}, phase, command, phase.completed); err == nil {
				t.Fatal("returned handle retained authority")
			}
		})
	}
}
