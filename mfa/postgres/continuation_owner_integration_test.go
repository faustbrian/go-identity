//go:build integration

package mfapostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpostgres "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identitycapability "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
)

// The native magic-link invocation and prior primary/factor bootstrap are fixture seams.
// Continuation persistence, child signing/issuance, parent use and audit/outbox
// use real owners. This is not a public MFA authentication journey.
type mfaIssuerPhase struct {
	command      identity.Command
	primary      identitypostgres.CapabilityPlan
	challenge    identitypostgres.MFAContinuationPlan
	issuer       *identitycapability.Issuer
	prepared     identitycapability.PreparedIssuance
	denyCommit   bool
	finalPlan    identitypostgres.CommandPlan
	continuation mfa.PartialAuthContinuation
	checkpoint   string
}

func (*mfaIssuerPhase) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}
}
func (p *mfaIssuerPhase) FeatureOperations() []identity.FeatureOperation {
	s, _ := p.command.Feature()
	return []identity.FeatureOperation{s.Operation}
}
func (p *mfaIssuerPhase) ValidateFeatureCommand(c identity.Command, _ identitypostgres.CommandPlan) error {
	if c != p.command {
		return identity.InvalidInputError{}
	}
	return nil
}
func (p *mfaIssuerPhase) ValidateMagicLinkConsumption(c identity.Command, proof identitypostgres.CapabilityPlan) error {
	if c != p.command || proof != p.primary {
		return identity.InvalidInputError{}
	}
	return nil
}
func (p *mfaIssuerPhase) ValidateMagicLinkMFAChallenge(c identity.Command, scope identitypostgres.MFAContinuationPlan) error {
	if c != p.command || scope != p.challenge {
		return identity.InvalidInputError{}
	}
	return nil
}
func (p *mfaIssuerPhase) ApplyFeature(ctx context.Context, w identitypostgres.Work, c identity.Command) (identity.FeatureReceipt, error) {
	p.checkpoint = "apply"
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	m, err := w.MagicLinkMFAChallenge(p)
	if err != nil || m != p.challenge {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	s, _ := c.Feature()
	if err = PersistMagicLinkContinuation(ctx, w, p, c, p.continuation); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = p.issuer.Stage(ctx, w, p.prepared); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.checkpoint = "staged"
	return identity.FeatureReceipt{Operation: s.Operation}, nil
}
func (p *mfaIssuerPhase) CheckFeatureCommit(ctx context.Context, w identitypostgres.Work, c identity.Command) error {
	p.checkpoint = "commit-check"
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return err
	}
	if c != p.command || p.denyCommit {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
func (*mfaIssuerPhase) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity_mfa.continuations WHERE origin_command_id=$1)`, mustContinuationCommandBytes(string(b.CommandID)))
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	defer rows.Close()
	var present bool
	if !rows.Next() || rows.Scan(&present) != nil || rows.Next() || rows.Err() != nil {
		return identitypostgres.RecoveryUnknown, identity.UnavailableError{}
	}
	if present {
		return identitypostgres.RecoveryCommitted, nil
	}
	return identitypostgres.RecoveryNotCommitted, nil
}

// This fixture supplies original retained admission, not real risk/factor
// authority. It cannot be used as a production authentication adapter.
func (p *mfaIssuerPhase) ValidateFeaturePreparation(c identity.Command, plan identitypostgres.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}
func (*mfaIssuerPhase) AdmitFeaturePreparation(ctx context.Context, _ identitypostgres.Work, _ identity.Command) error {
	return ctx.Err()
}
func (p *mfaIssuerPhase) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	p.checkpoint = "generate"
	if c != p.command || generation == 0 {
		return nil, identity.InvalidInputError{}
	}
	s, _ := c.Feature()
	return []byte(string(s.Binding.CommandID) + ":" + strconv.FormatUint(generation, 10)), ctx.Err()
}
func (p *mfaIssuerPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, identitypostgres.CommandPlan, error) {
	expected, err := p.GenerateFeaturePreparation(ctx, c, generation)
	if err != nil || string(expected) != string(wire) {
		return identity.Command{}, identitypostgres.CommandPlan{}, identity.InvalidInputError{}
	}
	p.checkpoint = "restore"
	return c, p.finalPlan, nil
}
func (p *mfaIssuerPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (identitypostgres.FeaturePreparationAdmission, error) {
	if c != p.command {
		return nil, identity.InvalidInputError{}
	}
	return mfaIssuerAdmission{p}, ctx.Err()
}
func (p *mfaIssuerPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identitypostgres.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	return mfaIssuerAdmission{p}, nil
}

type mfaIssuerAdmission struct{ phase *mfaIssuerPhase }

func (a mfaIssuerAdmission) Check(ctx context.Context) error { return ctx.Err() }
func (a mfaIssuerAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	return a.phase.GenerateFeaturePreparation(ctx, a.phase.command, generation)
}

func testMFAIssuance(t *testing.T, ctx context.Context, pool *database.Pool, repo *identitypostgres.Repository, auditing *auditpostgres.IdentityContributor, lifecycle *identityoutbox.Contributor) {
	history, err := (ContinuationMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if _, err = pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','mfa-user','active',1);
INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(repeat('01',16),'hex'),'tenant-a','identity.password.signup',decode(repeat('01',32),'hex'),1,decode('01','hex'));
INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(repeat('01',16),'hex'),'tenant-a','identity.password.signup');
INSERT INTO identity_mfa.factor_authorities VALUES('tenant-a','mfa-user',2,1,decode(repeat('01',16),'hex'),'identity.password.signup')`); err != nil {
		t.Fatal(err)
	}
	crypto, factorID := testTOTPStorage(t, ctx, pool)
	for _, mode := range []string{"wrong-origin", "wrong-parent", "wrong-remember", "empty-factor", "stale-factor", "commit", "late-denial", "recovery-absent", "recovery-identity", "recovery-replay", "recovery-origin", "native-completion-denied", "native-completion"} {
		t.Run(mode, func(t *testing.T) {
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			childID, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			b := identity.CommandBinding{CommandID: id, TenantID: "tenant-a", AnonymousFlowID: string(id), ActorID: "mfa-actor", ActorKind: authorization.SubjectUser, OperationID: "identity.magic-link.consume", SchemaID: "magic-link-consume", SchemaVersion: 1, PolicyID: "test-policy", PolicyVersion: 1, CorrelationID: "mfa-correlation"}
			op := identity.FeatureOperation{Owner: "identity/magiclink", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
			now := time.Now().UTC().Truncate(time.Second)
			key := []byte("0123456789abcdef0123456789abcdef")
			signer, err := capability.NewHMACSHA256Signer("signing-v1", key)
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := capability.NewHMACSHA256Verifier(key)
			if err != nil {
				t.Fatal(err)
			}
			keys, err := capability.NewKeySet([]capability.Key{{ID: "signing-v1", Verifier: verifier}})
			if err != nil {
				t.Fatal(err)
			}
			issuer, err := identitycapability.NewIssuer(identitycapability.IssuerConfig{Crypto: capability.ServiceConfig{Signer: signer, Resolver: keys, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()}, Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {1}}, PreparationTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			parent := capability.Payload{Version: 1, Issuer: "https://identity.example.test", Audiences: []string{"identity"}, Subject: "mfa-user", Tenant: "tenant-a", ID: "parent-" + string(id), Resource: "identity.magiclink/email-id", Operation: b.OperationID, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(10 * time.Minute), MaxUses: 1, Caveats: map[string]string{"magiclink.identifier": "email-id"}}
			token, err := capability.Issue(ctx, parent, signer, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			proof, err := capability.ParseProof(token, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
			grant, err := capability.Verify(ctx, token, keys, capability.VerifyOptions{Now: now, Limits: capability.DefaultLimits()})
			if err != nil {
				t.Fatal(err)
			}
			primary, err := issuer.PrepareMagicLinkConsumption(ctx, b, "mfa-user", "email-id", proof, grant.EnvelopeDigest(), 1)
			if err != nil {
				t.Fatal(err)
			}
			// Seed the prior primary issuance only; child issuance below must be native.
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses) VALUES($1,$2,$3,$4,$5,$6,$7,1)`, string(b.TenantID), string(primary.Purpose), int64(primary.ReplayKeyVersion), primary.ReplayDigest[:], primary.CapabilityID, primary.ProofFingerprint[:], primary.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			m := identitypostgres.MFAContinuationPlan{ID: childID, UserID: "mfa-user", ScopeDigest: [32]byte{7}, PolicyVersion: 1, FactorVersion: 2, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
			remember, err := session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			continuation, err := mfa.NewPartialAuthContinuation(mfa.ContinuationSpec{ID: mfa.ContinuationID(childID), PrimaryProofID: auth.ProofID(primary.CapabilityID), PrimaryProofDigest: primary.ProofFingerprint, PrimaryProofExpiresAt: primary.ExpiresAt, TenantID: b.TenantID, SubjectID: "mfa-user", SourcePreAuthID: identity.PreAuthTransactionID(b.AnonymousFlowID), Origin: "https://app.test", AllowedMethods: []string{"totp"}, PolicyVersion: 1, FactorVersion: 2, RememberPolicy: remember, Purpose: "identity.mfa.complete", Audience: "identity", IssuedAt: now, ExpiresAt: m.ExpiresAt, MaxAttempts: 3, AttemptsRemaining: 3, State: mfa.Pending, Version: 1})
			if err != nil {
				t.Fatal(err)
			}
			m.ScopeDigest, err = continuation.ScopeDigest()
			if err != nil {
				t.Fatal(err)
			}
			payload, err := continuation.CapabilityPayload(parent.Issuer)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := issuer.PrepareMFAContinuation(ctx, b, payload)
			if err != nil {
				t.Fatal(err)
			}
			issue, err := prepared.Plan()
			if err != nil {
				t.Fatal(err)
			}
			cmd, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "proof-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: primary.CapabilityID}}}})
			if err != nil {
				t.Fatal(err)
			}
			phase := &mfaIssuerPhase{command: cmd, primary: primary, challenge: m, issuer: issuer, prepared: prepared, continuation: continuation, denyCommit: mode == "late-denial"}
			if strings.HasPrefix(mode, "wrong-") {
				changed, _ := continuation.Bindings()
				switch mode {
				case "wrong-origin":
					changed.Origin = "https://foreign.test"
				case "wrong-parent":
					changed.PrimaryProofID = "foreign-proof"
				case "wrong-remember":
					policy, _ := changed.RememberPolicy.Bindings()
					policy.Choice = session.PersistentSession
					changed.RememberPolicy, err = session.NewRememberPolicy(policy)
					if err != nil {
						t.Fatal(err)
					}
				}
				phase.continuation, err = mfa.NewPartialAuthContinuation(changed)
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "empty-factor" || mode == "stale-factor" {
				active, version := 1, 2
				if mode == "empty-factor" {
					active = 0
				} else {
					version = 3
				}
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=$1,version=$2 WHERE tenant_id='tenant-a' AND user_id='mfa-user'`, active, version); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1,version=2 WHERE tenant_id='tenant-a' AND user_id='mfa-user'`); err != nil {
						t.Error(err)
					}
				}()
			}
			participant := identitycapability.NewParticipant()
			registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{repo, auditing, lifecycle, phase, participant, issuer})
			if err != nil {
				t.Fatal(err)
			}
			policy, err := authorization.NewDecisionService(testPolicy{})
			if err != nil {
				t.Fatal(err)
			}
			c, err := identitypostgres.NewCoordinator(pool, registry, identitypostgres.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}, QueryPolicy: &identitypostgres.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: policy}})
			if err != nil {
				t.Fatal(err)
			}
			builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { id, e := identity.NewSubjectID(); return string(id), e }})
			if err != nil {
				t.Fatal(err)
			}
			record, err := builder.Build(audit.RecordInput{Action: b.OperationID, OccurredAt: now, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "authentication_attempt", ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(id), "retention.class": "protected", "aggregate.type": "authentication_attempt", "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0"}})
			if err != nil {
				t.Fatal(err)
			}
			redactor, err := audit.NewRedactor(audit.RedactionRules{AllowedAttributes: []string{"identity.profile", "command.id", "retention.class", "aggregate.type", "aggregate.id", "aggregate.before_version", "aggregate.after_version"}})
			if err != nil {
				t.Fatal(err)
			}
			record, err = redactor.Redact(ctx, record)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := identitypostgres.FeatureAuditBindingDigest(b, op, "authentication_attempt", record)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := c.PrepareCommandPlan(b, cmd, identitypostgres.CommandPlan{Contributors: registry.Descriptors(), Feature: &identitypostgres.FeatureRegistration{Contributor: phase.Descriptor(), Operation: op}, SubjectType: "authentication_attempt", Audits: []identitypostgres.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "mfa.challenge.created.v1"}, Capability: &primary, MFAContinuation: &m, CapabilityIssuance: &issue})
			if err != nil {
				t.Fatal("prepare challenge", err)
			}
			phase.finalPlan = plan
			query := identity.RecoveryQuery{CommandID: id, TenantID: b.TenantID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID}
			caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.ActorID)}, Tenant: authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(b.AnonymousFlowID)}}}
			if strings.HasPrefix(mode, "recovery-") {
				if _, _, err := c.ReserveCommand(ctx, b, cmd, plan); err != nil {
					t.Fatal("reserve challenge", err)
				}
				child := issue.Grants[0]
				if mode != "recovery-absent" {
					capID, replay, origin := "conflicting-"+string(id), sha256.Sum256([]byte("conflicting-"+string(id))), ""
					if mode == "recovery-identity" {
						capID = child.CapabilityID
					}
					if mode == "recovery-replay" {
						replay = child.ReplayDigest
					}
					if mode == "recovery-origin" {
						origin = string(id)
					}
					if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses,origin_command_id,origin_fingerprint,origin_generation,subject_id,signed_issued_at,signed_not_before,signing_key_id,payload_digest,created_at) VALUES($1,$2,$3,$4,$5,$6::bytea,$7,1,NULLIF($8::text,''),CASE WHEN $8='' THEN NULL ELSE $6::bytea END,CASE WHEN $8='' THEN NULL ELSE 1 END,CASE WHEN $8='' THEN NULL ELSE 'conflicting-user' END,CASE WHEN $8='' THEN NULL ELSE $9::timestamptz END,CASE WHEN $8='' THEN NULL ELSE $9::timestamptz END,CASE WHEN $8='' THEN NULL ELSE 'signing-v1' END,CASE WHEN $8='' THEN NULL ELSE $6::bytea END,CASE WHEN $8='' THEN NULL ELSE $9::timestamptz END)`, string(b.TenantID), string(child.Purpose), int64(child.ReplayKeyVersion), replay[:], capID, child.ProofFingerprint[:], child.ExpiresAt, origin, now); err != nil {
						t.Fatal(err)
					}
				}
				key, _ := base64.RawURLEncoding.DecodeString(string(id))
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, key); err != nil {
					t.Fatal(err)
				}
				recovered, recoveryErr := c.RecoverFeatureCommand(ctx, query, caller)
				if mode == "recovery-absent" {
					if recovered.Outcome != identity.CommitOutcomeNotCommitted || recovered.Binding != b {
						t.Fatal("original absent producer did not prove rollback", recovered.Outcome, recoveryErr)
					}
				} else if recoveryErr == nil || recovered.Outcome != identity.CommitOutcomeInProgress {
					t.Fatal("conflicting child fabricated noncommit", recovered.Outcome, recoveryErr)
				}
				return
			}
			original := plan
			original.CapabilityIssuance = nil
			original.Contributors = plan.Contributors[:len(plan.Contributors)-1]
			original, err = c.PrepareFeaturePreparationPlan(cmd, original)
			if err != nil {
				t.Fatal("prepare original challenge", err)
			}
			result, err := c.ExecutePreparedFeature(ctx, cmd, original)
			var children, continuations int
			var uses int32
			if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.capability_identity_one_use WHERE origin_command_id=$1),(SELECT count(*) FROM identity_mfa.continuations WHERE origin_command_id=$3),(SELECT uses FROM public.capability_identity_one_use WHERE capability_id=$2)`, string(id), primary.CapabilityID, mustContinuationCommandBytes(string(id))).Scan(&children, &continuations, &uses); e != nil {
				t.Fatal(e)
			}
			if mode == "late-denial" || strings.HasPrefix(mode, "wrong-") || mode == "empty-factor" || mode == "stale-factor" {
				if err == nil || children != 0 || continuations != 0 || uses != 0 {
					t.Fatal("late denial retained issuance or primary use", err)
				}
				return
			}
			if err != nil || result.Outcome != identity.CommitOutcomeCommitted || children != 1 || continuations != 1 || uses != 1 {
				t.Fatal("split native MFA issuance", phase.checkpoint, err)
			}
			reader, err := NewContinuationReader(pool, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			childToken, err := capability.Issue(ctx, payload, signer, capability.DefaultLimits())
			if err != nil {
				t.Fatal("child proof unavailable")
			}
			childGrant, err := capability.Verify(ctx, childToken, keys, capability.VerifyOptions{Now: now, Limits: capability.DefaultLimits()})
			if err != nil {
				t.Fatal("child verification unavailable")
			}
			loaded, err := reader.Read(ctx, childGrant, parent.Issuer)
			if err != nil {
				t.Fatal("committed original continuation unavailable", err)
			}
			if mode == "commit" {
				testTOTPFactorRead(t, ctx, pool, childGrant, parent.Issuer, factorID, crypto)
			}
			loadedScope, _ := loaded.Bindings()
			originalScope, _ := continuation.Bindings()
			if !reflect.DeepEqual(loadedScope, originalScope) {
				t.Fatal("public reader replaced original scope")
			}
			if _, err := reader.Read(ctx, grant, parent.Issuer); err == nil {
				t.Fatal("primary grant read child scope")
			}
			if _, err := reader.Read(ctx, childGrant, "https://foreign.test"); err == nil {
				t.Fatal("foreign issuer read child scope")
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=3 WHERE tenant_id='tenant-a' AND user_id='mfa-user'`); err != nil {
				t.Fatal(err)
			}
			if _, err := reader.Read(ctx, childGrant, parent.Issuer); err == nil {
				t.Fatal("stale factor authority read pending continuation")
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2 WHERE tenant_id='tenant-a' AND user_id='mfa-user'`); err != nil {
				t.Fatal(err)
			}
			var subject, capabilityID, origin string
			var issuedAt, expiresAt time.Time
			var fingerprint, replayDigest, payloadDigest []byte
			if err := pool.Raw().QueryRow(ctx, `SELECT subject_id,capability_id,origin_command_id,signed_issued_at,expires_at,proof_fingerprint,replay_digest,payload_digest FROM public.capability_identity_one_use WHERE origin_command_id=$1`, string(id)).Scan(&subject, &capabilityID, &origin, &issuedAt, &expiresAt, &fingerprint, &replayDigest, &payloadDigest); err != nil {
				t.Fatal(err)
			}
			child := issue.Grants[0]
			canonical, err := capability.CanonicalPayload(payload, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			expectedPayloadDigest := sha256.Sum256(canonical)
			clear(canonical)
			if subject != string(m.UserID) || capabilityID != string(m.ID) || origin != string(id) || !issuedAt.Equal(m.IssuedAt) || !expiresAt.Equal(m.ExpiresAt) || string(fingerprint) != string(child.ProofFingerprint[:]) || string(replayDigest) != string(child.ReplayDigest[:]) || string(payloadDigest) != string(expectedPayloadDigest[:]) {
				t.Fatal("durable child metadata diverged from original signed issuance")
			}
			var storedScope, storedDigest []byte
			var state uint8
			var versionText string
			var remaining uint32
			if err := pool.Raw().QueryRow(ctx, `SELECT original_scope,scope_digest,state,version::text,attempts_remaining FROM identity_mfa.continuations WHERE tenant_id=$1 AND continuation_id=$2`, string(b.TenantID), string(m.ID)).Scan(&storedScope, &storedDigest, &state, &versionText, &remaining); err != nil {
				t.Fatal(err)
			}
			if string(storedDigest) != string(m.ScopeDigest[:]) {
				t.Fatal("stored original scope digest changed")
			}
			version, err := strconv.ParseUint(versionText, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			stored, err := decodeContinuationScope(storedScope, m.ScopeDigest, mfa.ContinuationState(state), version, remaining)
			clear(storedScope)
			if err != nil {
				t.Fatal("stored original scope cannot be restored", err)
			}
			storedBindings, _ := stored.Bindings()
			originalBindings, _ := continuation.Bindings()
			if !reflect.DeepEqual(storedBindings, originalBindings) {
				t.Fatal("durable original scope or attempt budget changed")
			}
			if replay, err := c.ExecutePreparedFeature(ctx, cmd, original); err != nil || replay.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("original challenge retry lost receipt", err)
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_mfa.continuations WHERE origin_command_id=$1`, mustContinuationCommandBytes(string(id))).Scan(&continuations); err != nil || continuations != 1 {
				t.Fatal("retry duplicated or removed original continuation", err)
			}
			recovered, err := c.RecoverFeatureCommand(ctx, query, caller)
			if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Binding != b {
				t.Fatal("durable child receipt lost", err)
			}
			if mode == "commit" || strings.HasPrefix(mode, "native-completion") {
				childProof, e := capability.ParseProof(childToken, capability.DefaultLimits())
				if e != nil {
					t.Fatal(e)
				}
				defer childProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
				if strings.HasPrefix(mode, "native-completion") {
					testNativeTOTPCompletion(t, ctx, pool, repo, auditing, lifecycle, childProof, issuer, parent.Issuer, factorID, crypto, id, mode == "native-completion-denied")
				} else {
					testNativeTOTPAttempt(t, ctx, pool, repo, auditing, lifecycle, childProof, issuer, parent.Issuer, factorID, crypto, issue.Grants[0])
				}
			}
		})
	}
}

func mustContinuationCommandBytes(id string) []byte {
	b, _ := base64.RawURLEncoding.DecodeString(id)
	return b
}
