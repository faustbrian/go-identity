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
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	identitycapability "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
)

// This closed native feature/counter seam exercises real capability, pre-auth
// and session persistence under the actual coordinator. Original signed proof,
// cookie possession and factor/risk decisions remain public-workflow obligations;
// synthetic grant metadata here is not cryptographic or login evidence.
type magicLinkEffectFeature struct {
	registration          *kernel.MagicLinkRegistrationDomain
	intent                *kernel.MagicLinkRegistrationIntent
	duplicateFactors      bool
	stage                 string
	effect                *MagicLinkSigninEffect
	expected              identity.Command
	proof                 kernel.CapabilityPlan
	recipient             kernel.RecipientRecord
	flow                  session.PreAuthTransaction
	failApply, failCommit bool
}

func (p *magicLinkEffectFeature) MagicLinkRegistration(c identity.Command) (kernel.MagicLinkRegistrationIntent, error) {
	if c != p.expected || p.intent == nil {
		return kernel.MagicLinkRegistrationIntent{}, identity.InvalidInputError{Field: "magic_registration"}
	}
	return *p.intent, nil
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
	if p.intent != nil {
		p.stage = "creation"
		if _, err := p.registration.Apply(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
		p.stage = "factor initialization"
		if err := mfapg.InitializeMagicLinkSignup(ctx, w, p, c, p.intent.Creation.Binding.UserID); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if p.duplicateFactors {
			if err := mfapg.InitializeMagicLinkSignup(ctx, w, p, c, p.intent.Creation.Binding.UserID); err != nil {
				return identity.FeatureReceipt{}, err
			}
		}
		if _, err := mfapg.RequireMagicLinkFactors(ctx, w, p, c, p.intent.Creation.Binding.UserID, 1); err != nil {
			return identity.FeatureReceipt{}, err
		}
		p.stage = "recipient selection"
		current, err := p.registration.Recipient(ctx, w, p, c)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		p.recipient = current
		p.stage = "policy initialization"
		if _, err := policy.InitializeAuthority(ctx, w, policy.AuthorityScope{TenantID: authorization.TenantID(current.User.TenantID), PolicyNamespace: "users", SubjectID: authorization.SubjectID(current.User.ID)}, time.Second); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	p.stage = "session effect"
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
	if p.intent != nil {
		if _, err := mfapg.RequireMagicLinkFactors(ctx, w, p, c, p.intent.Creation.Binding.UserID, 1); err != nil {
			return err
		}
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
	for _, history := range []struct {
		table string
		files fs.FS
	}{{"public.outbox_messages", outboxpg.Migrations()}, {"public.identity_outbox_bindings", lifecyclepg.Migrations()}} {
		var installed bool
		if err := pool.Raw().QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, history.table).Scan(&installed); err != nil {
			t.Fatal(err)
		}
		if installed {
			continue
		}
		paths, err := fs.Glob(history.files, "*.sql")
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			contents, err := fs.ReadFile(history.files, path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, strings.Split(string(contents), "-- +migrations Down")[0]); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Extend only this owned fixture; old histories remain byte-for-byte intact.
	acceptance, err := (kernel.PasswordSignupAcceptanceMigrationSource{Base: kernel.MigrationSource{}, Version: 41}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, acceptance[len(acceptance)-1].UpSQL()); err != nil {
		t.Fatal(err)
	}
	registrationHistory, err := (kernel.MagicLinkRegistrationMigrationSource{Base: fixtureSource(acceptance), Version: 42}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, registrationHistory[len(registrationHistory)-1].UpSQL()); err != nil {
		t.Fatal(err)
	}
	factorHistory, err := (mfapg.MagicLinkSignupMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range factorHistory {
		if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	capabilityHistory, err := fs.Glob(identitycapability.Migrations(), "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range capabilityHistory {
		contents, err := fs.ReadFile(identitycapability.Migrations(), path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Raw().Exec(ctx, strings.Split(string(contents), "-- +migrations Down")[0]); err != nil {
			t.Fatal(err)
		}
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
	registration, err := kernel.NewMagicLinkRegistrationDomain(domain, kernel.MagicLinkRegistrationDomainConfig{ComparisonProfile: "email-v1", EmailPossessionPolicyVersion: 3, CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "csrf", "apply-denied", "commit-denied", "audit-failure", "outbox-failure", "stale-user", "consumed-flow", "foreign-grant", "late-expiry", "signup", "signup-duplicate-factors", "signup-commit-denied", "signup-audit-failure", "signup-outbox-failure", "signup-native-outbox", "signup-native-outbox-failure"} {
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
			if strings.HasPrefix(mode, "signup") {
				recipient.User.ID, recipient.User.Version = identity.UserID("prospective-"+mode), 1
				recipient.Identifier.ID, recipient.Identifier.UserID, recipient.Identifier.CanonicalValue, recipient.Identifier.Primary = identity.IdentifierID("prospective-email-"+mode), recipient.User.ID, mode+"@example.test", false
				recipient.Identifier.Version, recipient.Verification.IdentifierID, recipient.Verification.Version, recipient.Verification.VerifiedAt = 1, recipient.Identifier.ID, 1, now
				recipient.Query.CanonicalValue, recipient.ObservedAt = recipient.Identifier.CanonicalValue, now
			}
			_, original := magicLinkSigninMappingFixture(t, false)
			s, _ := original.Bindings()
			s.TenantID, s.UserID, s.SessionID, s.FamilyID = b.TenantID, recipient.User.ID, "magic-session-"+mode, "magic-family-"+mode
			s.IssuedAt, s.LastActivityAt, s.Lookup = now, now, session.TokenDigest{KeyVersion: 1, Sum: sha256.Sum256([]byte("session-fixture/" + mode))}
			keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: b.TenantID}, s.UserID)
			sk, _ := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
			pk, _ := (policy.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), PolicyNamespace: "users", SubjectID: authorization.SubjectID(s.UserID)}).Key()
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
			var intent *kernel.MagicLinkRegistrationIntent
			var declaration *kernel.MagicLinkRegistrationPlan
			if strings.HasPrefix(mode, "signup") {
				creation := b
				creation.OperationID, creation.AnonymousFlowID, creation.UserID, creation.SchemaID = "identity.user.create", "", recipient.User.ID, "identity-user"
				email := recipient.Identifier
				email.Verified = false
				intent = &kernel.MagicLinkRegistrationIntent{Creation: identity.CreateUserCommand{Binding: creation, Status: identity.StatusActive}, Identifier: email, ComparisonProfile: "email-v1", EmailPossessionPolicyVersion: 3}
				additional, err := kernel.MagicLinkRegistrationFields(*intent)
				if err != nil {
					t.Fatal(err)
				}
				fields = append(fields, additional...)
				digest, err := kernel.MagicLinkRegistrationDigest(*intent)
				if err != nil {
					t.Fatal(err)
				}
				declaration = &kernel.MagicLinkRegistrationPlan{UserID: recipient.User.ID, IdentifierID: string(email.ID), CreationDigest: digest, EmailPossessionPolicyVersion: 3, CreationEventIndex: 1}
			}
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: magicLinkSessionOperation(), Fields: fields})
			if err != nil {
				t.Fatal(err)
			}
			native := &magicLinkEffectFeature{registration: registration, intent: intent, duplicateFactors: mode == "signup-duplicate-factors", effect: effect, expected: command, proof: proof, recipient: recipient, flow: flow, failApply: mode == "apply-denied", failCommit: mode == "commit-denied" || mode == "signup-commit-denied"}
			if mode == "foreign-grant" {
				native.proof.CapabilityID = "different-grant"
			}
			var outbox kernel.Contributor = &revokeOutbox{fail: mode == "outbox-failure" || mode == "signup-outbox-failure"}
			actualOutbox := strings.HasPrefix(mode, "signup-native-outbox")
			if actualOutbox {
				outbox, err = lifecyclepg.NewContributor()
				if err != nil {
					t.Fatal(err)
				}
			}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, &revokeAudit{fail: mode == "audit-failure" || mode == "signup-audit-failure"}, outbox, native, &magicLinkEffectCounters{}, identitycapability.NewParticipant()})
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
			plan, err := c.PrepareCommandPlan(b, command, kernel.CommandPlan{MagicLinkRegistration: declaration, Contributors: registry.Descriptors(), SubjectType: "authentication_attempt", Feature: &kernel.FeatureRegistration{Contributor: native.Descriptor(), Operation: magicLinkSessionOperation()}, Capability: &proof, CommandCounters: &kernel.CommandCounterPlan{PolicyVersion: 1, Fingerprint: [32]byte{3}}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1"}, Audits: []kernel.AuditPlan{{EventType: "authentication.succeeded", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
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
				if mode == "signup-native-outbox-failure" {
					// Fail the real second INSERT, after the login event prefix.
					if _, e := pool.Raw().Exec(ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT reject_magiclink_creation CHECK(topic <> 'user.created.v1') NOT VALID`); e != nil {
						t.Fatal(e)
					}
					defer func() {
						if _, e := pool.Raw().Exec(ctx, `ALTER TABLE public.outbox_messages DROP CONSTRAINT reject_magiclink_creation`); e != nil {
							t.Error("outbox fault cleanup")
						}
					}()
				}
				result, err = c.Commit(w, result)
			}
			want := 0
			if mode == "commit" || mode == "csrf" || mode == "signup" || mode == "signup-native-outbox" {
				want = 1
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("commit", native.stage, err)
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
			if intent != nil {
				var users, emails, factors, bindings, passwords, createdEvents int
				if err := pool.Raw().QueryRow(ctx, `SELECT
(SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2 AND status='active' AND version=1),
(SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND verified AND verification_state=2 AND verified_at IS NOT NULL),
(SELECT count(*) FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2 AND version=1 AND active_factors=0 AND initialized_command_id=$4 AND initialized_purpose='identity.magic-link.consume'),
(SELECT count(*) FROM identity.registration_bindings WHERE tenant_id=$1 AND user_id=$2 AND command_id=$4 AND credential_id IS NULL AND NOT accepted_only),
(SELECT count(*) FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2),
(SELECT count(*) FROM public.revoke_outbox WHERE command_id=$5 AND event_type='user.created.v1' AND subject_id=$2 AND before_version='0' AND after_version='1')`, string(b.TenantID), string(s.UserID), string(intent.Identifier.ID), mustCommandBytes(t, b.CommandID), string(b.CommandID)).Scan(&users, &emails, &factors, &bindings, &passwords, &createdEvents); err != nil || users != want || emails != want || factors != want || bindings != want || passwords != 0 || !actualOutbox && createdEvents != want || actualOutbox && createdEvents != 0 {
					t.Fatalf("atomic signup effects %d/%d/%d/%d/passwords=%d/events=%d: %v", users, emails, factors, bindings, passwords, createdEvents, err)
				}
			}
			if actualOutbox {
				var messages, bindings, login, creation int
				if err := pool.Raw().QueryRow(ctx, `SELECT
(SELECT count(*) FROM public.outbox_messages WHERE convert_from(payload,'UTF8')::jsonb->>'command_id'=$1),
(SELECT count(*) FROM public.identity_outbox_bindings WHERE tenant_id=$2 AND command_id=$3),
(SELECT count(*) FROM public.outbox_messages WHERE topic='session.created.v1' AND convert_from(payload,'UTF8')::jsonb->>'command_id'=$1 AND convert_from(payload,'UTF8')::jsonb->>'subject_id'=$4),
(SELECT count(*) FROM public.outbox_messages WHERE topic='user.created.v1' AND convert_from(payload,'UTF8')::jsonb->>'command_id'=$1 AND convert_from(payload,'UTF8')::jsonb->>'subject_id'=$5 AND convert_from(payload,'UTF8')::jsonb->>'before_version'='0' AND convert_from(payload,'UTF8')::jsonb->>'after_version'='1')`, string(b.CommandID), string(b.TenantID), mustCommandBytes(t, b.CommandID), b.AnonymousFlowID, string(s.UserID)).Scan(&messages, &bindings, &login, &creation); err != nil || messages != 2*want || bindings != 2*want || login != want || creation != want {
					t.Fatalf("real paired outbox %d/%d/login=%d/creation=%d: %v", messages, bindings, login, creation, err)
				}
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
	t.Run("native MFA completion session", func(t *testing.T) { testNativeMFASessionEffect(t, ctx, pool) })
}
