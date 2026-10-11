//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	policy "github.com/faustbrian/go-authorization/postgres"
	identitycapability "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// This closed native feature/counter seam exercises real capability, pre-auth
// and session persistence under the actual coordinator. Original signed proof,
// cookie possession and factor/risk decisions remain public-workflow obligations;
// synthetic grant metadata here is not cryptographic or login evidence.
type magicLinkEffectFeature struct {
	effect                *MagicLinkSigninEffect
	expected              identity.Command
	proof                 kernel.CapabilityPlan
	recipient             kernel.RecipientRecord
	flow                  session.PreAuthTransaction
	failApply, failCommit bool
}

func (*magicLinkEffectFeature) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}
}
func (*magicLinkEffectFeature) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{magicLinkSessionOperation()}
}
func (p *magicLinkEffectFeature) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.expected {
		return session.ErrInvalidSessionCommand
	}
	_, err := MagicLinkSigninSession(c)
	return err
}
func (p *magicLinkEffectFeature) ValidateMagicLinkConsumption(c identity.Command, proof kernel.CapabilityPlan) error {
	if c != p.expected || proof != p.proof {
		return session.ErrInvalidSessionCommand
	}
	return nil
}
func (p *magicLinkEffectFeature) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	r, err := p.effect.Apply(ctx, w, p, c, p.recipient, p.flow)
	if err == nil && p.failApply {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return r, err
}
func (p *magicLinkEffectFeature) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.failCommit {
		return identity.ForbiddenError{}
	}
	r, err := MagicLinkSigninSession(c)
	if err != nil {
		return err
	}
	return requireMagicLinkIssueTime(ctx, w, r)
}
func (p *magicLinkEffectFeature) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.effect.Recover(ctx, w, p)
}

type magicLinkEffectCounters struct{}

func (*magicLinkEffectCounters) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}
}
func (*magicLinkEffectCounters) ValidateCommandCounters(identity.Command, kernel.CommandCounterPlan) error {
	return nil
}
func (p *magicLinkEffectCounters) CheckCommandCounters(_ context.Context, w kernel.CommandCounterAdmissionWork) error {
	_, err := w.Binding(p)
	return err
}
func (*magicLinkEffectCounters) ReserveCommandCounters(context.Context, kernel.CommandCounterWork) (kernel.CommandCounterDisposition, error) {
	return kernel.CommandCounterAllowed, nil
}
func (*magicLinkEffectCounters) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryNotCommitted, nil
}

func testNativeMagicLinkSessionEffect(t *testing.T, ctx context.Context, pool *database.Pool) {
	contents, err := fs.ReadFile(identitycapability.Migrations(), "001_identity_one_use.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, strings.Split(string(contents), "-- +migrations Down")[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.tenant_authorities(tenant_id,version,enabled) VALUES('magic-effect',1,true);
INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('magic-effect','recipient','active',1);
INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('magic-effect','recipient','magic-email','email','magic@example.test',true,true,1,2,1,clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	scope := policy.AuthorityScope{TenantID: "magic-effect", PolicyNamespace: "users", SubjectID: "recipient"}
	if _, err := policy.InitializeAuthority(ctx, pool.Raw(), scope, time.Second); err != nil {
		t.Fatal(err)
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	profile := MagicLinkAdmissionConfig{GlobalAuthorityID: "deployment-issue", PolicyNamespace: "users", Audience: "service-a"}
	effect, err := NewMagicLinkSigninEffect(config, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "csrf", "apply-denied", "commit-denied", "audit-failure", "outbox-failure", "stale-user", "consumed-flow", "foreign-grant", "late-expiry"} {
		t.Run(mode, func(t *testing.T) {
			b := revokeBinding()
			b.CommandID, _ = identity.NewCommandID()
			b.TenantID, b.UserID, b.RecordID, b.AnonymousFlowID = "magic-effect", "", "", "original-flow-"+mode
			b.OperationID, b.SchemaID = "identity.magic-link.consume", "magic-link-consume"
			recipient, err := domain.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: b.TenantID, Kind: identity.IdentifierEmail, CanonicalValue: "magic@example.test", Eligibility: kernel.RecipientVerified})
			if err != nil {
				t.Fatal(err)
			}
			var now time.Time
			if err := pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal(err)
			}
			now = now.UTC()
			_, original := magicLinkSigninMappingFixture(t, false)
			s, _ := original.Bindings()
			s.TenantID, s.UserID, s.SessionID, s.FamilyID = b.TenantID, recipient.User.ID, "magic-session-"+mode, "magic-family-"+mode
			s.IssuedAt, s.LastActivityAt, s.Lookup = now, now, session.TokenDigest{KeyVersion: 1, Sum: sha256.Sum256([]byte("session-fixture/" + mode))}
			keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: b.TenantID}, s.UserID)
			sk, _ := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
			pk, _ := scope.Key()
			a := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
			s.Authority, err = session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: a(keys.Global), Tenant: a(keys.Tenant), User: a(keys.User), Identifier: a(keys.Identifier), Credential: a(keys.Credential), SessionFamily: a(sk.Family), Session: a(sk.Session), Authorization: a(pk)})
			if err != nil {
				t.Fatal(err)
			}
			p, _ := original.MagicLinkAuthentication().Bindings()
			p.CommandID, p.CapabilityID, p.IdentifierID = b.CommandID, "magic-grant-"+mode, recipient.Identifier.ID
			p.IdentifierVersion, p.VerificationVersion, p.AuthenticatedAt, p.ValidUntil = recipient.Identifier.Version, recipient.Verification.Version, now, now.Truncate(time.Second).Add(time.Minute)
			if mode == "late-expiry" {
				p.ValidUntil = now.Truncate(time.Second).Add(2 * time.Second)
			}
			meta, err := session.NewMagicLinkAuthentication(p)
			if err != nil {
				t.Fatal(err)
			}
			record, err := session.NewSessionWithMagicLink(s, meta)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "csrf" {
				state, err := session.NewCSRFState(session.CSRFStateSpec{Binding: session.CSRFBinding{TenantID: s.TenantID, SessionID: s.SessionID, SessionVersion: 1}, KeyVersion: 1, Digest: [32]byte{1}})
				if err != nil {
					t.Fatal(err)
				}
				record, err = session.NewSessionWithMagicLinkAndCSRF(s, meta, state)
				if err != nil {
					t.Fatal(err)
				}
			}
			flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: identity.PreAuthTransactionID(b.CommandID), Intent: session.PreAuthIntent{TenantID: b.TenantID, Action: b.OperationID, Origin: "https://app.example.test", CallbackURL: "https://app.example.test/login", Nonce: [32]byte{1}, Remember: s.Remember, PolicyID: b.PolicyID, PolicyVersion: b.PolicyVersion}, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(5 * time.Minute)}, Cookie: session.TokenDigest{KeyVersion: 1, Sum: sha256.Sum256([]byte("preauth-fixture/" + mode))}, Version: 1})
			if err != nil {
				t.Fatal(err)
			}
			wire, err := encodePreAuth(flow)
			if err != nil {
				t.Fatal(err)
			}
			fs, _ := flow.Bindings()
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.preauth_transactions(tenant_id,flow_id,record,issued_at,expires_at,digest_version,digest,issued_version,version,state) VALUES($1,$2,$3,$4,$5,1,$6,1,1,'issued')`, string(b.TenantID), string(fs.Binding.ID), wire, fs.Binding.IssuedAt.Format(storedTimeLayout), fs.Binding.ExpiresAt.Format(storedTimeLayout), fs.Cookie.Sum[:]); err != nil {
				t.Fatal(err)
			}
			proof := kernel.CapabilityPlan{CapabilityID: p.CapabilityID, Purpose: "identity.magic-link.consume", ReplayDigest: sha256.Sum256([]byte("grant-fixture/" + mode)), ReplayKeyVersion: 1, ProofFingerprint: [32]byte{2}, ExpiresAt: p.ValidUntil, MaxUses: 1}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses) VALUES($1,$2,1,$3,$4,$5,$6,1)`, string(b.TenantID), string(proof.Purpose), proof.ReplayDigest[:], proof.CapabilityID, proof.ProofFingerprint[:], proof.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			fields, err := MagicLinkSigninSessionFields(record)
			if err != nil {
				t.Fatal(err)
			}
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: magicLinkSessionOperation(), Fields: fields})
			if err != nil {
				t.Fatal(err)
			}
			native := &magicLinkEffectFeature{effect: effect, expected: command, proof: proof, recipient: recipient, flow: flow, failApply: mode == "apply-denied", failCommit: mode == "commit-denied"}
			if mode == "foreign-grant" {
				native.proof.CapabilityID = "different-grant"
			}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, &revokeAudit{fail: mode == "audit-failure"}, &revokeOutbox{fail: mode == "outbox-failure"}, native, &magicLinkEffectCounters{}, identitycapability.NewParticipant()})
			if err != nil {
				t.Fatal(err)
			}
			c, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: "authentication.succeeded", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "authentication_attempt", ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: fmt.Sprint(b.PolicyVersion)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "authentication_attempt", "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(b, magicLinkSessionOperation(), "authentication_attempt", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := c.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "authentication_attempt", Feature: &kernel.FeatureRegistration{Contributor: native.Descriptor(), Operation: magicLinkSessionOperation()}, Capability: &proof, CommandCounters: &kernel.CommandCounterPlan{PolicyVersion: 1, Fingerprint: [32]byte{3}}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1"}, Audits: []kernel.AuditPlan{{EventType: "authentication.succeeded", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
			if mode == "foreign-grant" {
				if err == nil {
					t.Fatal("native grant mismatch admitted")
				}
				return
			}
			if err != nil {
				t.Fatal("prepare", err)
			}
			reservation, _, err := c.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal("reserve", err)
			}
			if mode == "stale-user" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET authority_version=2 WHERE tenant_id='magic-effect'`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					_, _ = pool.Raw().Exec(ctx, `UPDATE identity.users SET authority_version=1 WHERE tenant_id='magic-effect'`)
				}()
			}
			if mode == "consumed-flow" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.preauth_transactions SET state='consumed',version=3,command_id=$3,fingerprint=$4,generation=1 WHERE tenant_id=$1 AND flow_id=$2`, string(b.TenantID), string(fs.Binding.ID), mustCommandBytes(t, b.CommandID), proof.ProofFingerprint[:]); err != nil {
					t.Fatal(err)
				}
			}
			w, err := c.Begin(ctx, reservation)
			if err != nil {
				t.Fatal("begin", err)
			}
			defer c.Abort(w, identity.UnavailableError{})
			result, err := c.ApplyFeature(ctx, w, command)
			if err == nil && mode == "late-expiry" {
				if _, e := pool.Raw().Exec(ctx, `SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())))+0.01)`, p.ValidUntil); e != nil {
					t.Fatal(e)
				}
			}
			if err == nil {
				result, err = c.Commit(w, result)
			}
			want := 0
			if mode == "commit" || mode == "csrf" {
				want = 1
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("commit", err)
				}
				_, replay, err := c.ReserveCommand(ctx, b, command, plan)
				if err != nil || replay.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("retained replay", err)
				}
			} else {
				if err == nil {
					t.Fatal("denied effect committed")
				}
				_, _ = c.Abort(w, err)
			}
			var sessions, families, issuances, uses int
			var state, flowState string
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2),(SELECT count(*) FROM session_store.families WHERE tenant_id=$1 AND family_id=$3),(SELECT count(*) FROM session_store.session_issuances WHERE command_id=$4),(SELECT uses FROM public.capability_identity_one_use WHERE capability_id=$5),(SELECT state FROM public.capability_identity_one_use WHERE capability_id=$5),(SELECT state FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$6)`, string(b.TenantID), s.SessionID, s.FamilyID, mustCommandBytes(t, b.CommandID), proof.CapabilityID, string(fs.Binding.ID)).Scan(&sessions, &families, &issuances, &uses, &state, &flowState); err != nil || sessions != want || families != want || issuances != want || uses != want {
				t.Fatalf("atomic effects %d/%d/%d/%d: %v", sessions, families, issuances, uses, err)
			}
			if want == 1 {
				if state != "finalized" || flowState != "consumed" {
					t.Fatal("capability/pre-auth not finalized")
				}
				repository, _ := NewRepository(pool, config)
				stored, err := repository.Get(ctx, s.TenantID, s.SessionID)
				if err != nil {
					t.Fatal(err)
				}
				a, _, _ := encodeRecord(record)
				b, _, _ := encodeRecord(stored.Session)
				if !bytes.Equal(a, b) {
					t.Fatal("persisted original session changed")
				}
				for _, pruned := range []bool{false, true} {
					if pruned {
						if _, err := pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2`, string(s.TenantID), s.SessionID); err != nil {
							t.Fatal(err)
						}
					}
					retained, status, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, result.Binding, kernel.LifecyclePlan{}, magicLinkIssuanceDigest)
					if err != nil || status != kernel.RecoveryCommitted || retained.UserID != s.UserID || retained.SessionID != s.SessionID || retained.FamilyID != s.FamilyID {
						t.Fatal("lost retained original session identity", err)
					}
					_, wrong, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, result.Binding, kernel.LifecyclePlan{}, passwordIssuanceDigest)
					if err != nil || wrong != kernel.RecoveryUnknown {
						t.Fatal("magic-link evidence borrowed password digest domain", err)
					}
				}
			} else if state != "reserved" && state != "released" || flowState != "issued" && mode != "consumed-flow" {
				t.Fatal("denied transaction consumed original grant or flow", state, flowState)
			}
		})
	}
}
