//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	capability "github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
)

// Component-owner proof only. Counter/capability test participants deliberately
// do not authenticate a guest/target or verify a signature. The real native
// anonymous workflow must prove those owners and fresh target reauthentication.
type anonymousUpgradeSessionFeature struct {
	domain     *kernel.AnonymousDisposalDomain
	effect     *AnonymousUpgradeEffect
	intent     kernel.AnonymousDisposalIntent
	command    identity.Command
	guest      session.Session
	permanent  session.Session
	until      time.Time
	capability kernel.CapabilityPlan
	mode       string
	applied    bool
}

func (*anonymousUpgradeSessionFeature) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}
}
func (*anonymousUpgradeSessionFeature) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{anonymousUpgradeSessionOperation()}
}
func (p *anonymousUpgradeSessionFeature) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.command {
		return session.ErrInvalidSessionCommand
	}
	return ValidateAnonymousUpgradeSessionIntent(c, p.guest, p.permanent)
}
func (p *anonymousUpgradeSessionFeature) ValidateAnonymousUpgrade(c identity.Command, proof kernel.CapabilityPlan) error {
	if proof != p.capability {
		return session.ErrInvalidSessionCommand
	}
	return p.ValidateFeatureCommand(c, kernel.CommandPlan{})
}
func (p *anonymousUpgradeSessionFeature) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p.mode != "missing-disposal" {
		if _, err := p.domain.ApplyUpgrade(ctx, w, p, c, p.intent); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	actual := p
	if p.mode == "foreign-owner" {
		copy := *p
		actual = &copy
	}
	r, err := p.effect.Apply(ctx, w, actual, c, p.guest, p.permanent, p.until)
	p.applied = err == nil
	if err == nil && p.mode == "native-failure" {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	if err == nil && p.mode == "late-final" {
		_, err = w.Exec(ctx, `SELECT pg_sleep(0.6)`)
	}
	return r, err
}
func (p *anonymousUpgradeSessionFeature) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.mode == "final-failure" {
		return identity.ForbiddenError{}
	}
	if err := p.domain.CheckUpgrade(ctx, w, p, c, p.intent); err != nil {
		return err
	}
	return p.effect.Check(ctx, w, p, c, p.guest, p.permanent, p.until)
}
func (p *anonymousUpgradeSessionFeature) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.effect.Recover(ctx, w, p, p.guest)
}

func anonymousSessionOwnerPlan(t *testing.T, ctx context.Context, pool *database.Pool, repository *kernel.Repository, owner kernel.FeatureExecutionContributor, command identity.Command, transition kernel.LifecyclePlan, proof *kernel.CapabilityPlan, mode string) (*kernel.Coordinator, kernel.CommandPlan) {
	t.Helper()
	f, _ := command.Feature()
	b := f.Binding
	contributors := []kernel.Contributor{repository, &revokeAudit{fail: mode == "audit-failure"}, &revokeOutbox{fail: mode == "outbox-failure"}, owner}
	if proof != nil {
		contributors = append(contributors, &resetSessionCounter{}, &resetSessionCapability{})
	}
	registry, err := kernel.NewContributorRegistry(contributors)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	subjectType, subject := "anonymous", b.RecordID
	if proof == nil {
		subjectType, subject = "anonymous_flow", b.AnonymousFlowID
	}
	builder, _ := audit.NewBuilder(audit.BuilderConfig{})
	seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: subjectType, ID: subject}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: fmt.Sprint(b.PolicyVersion)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": subjectType, "aggregate.id": subject, "aggregate.before_version": strconv.FormatUint(transition.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(transition.AfterVersion, 10), "retention.class": "protected"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, f.Operation, subjectType, seed)
	if err != nil {
		t.Fatal(err)
	}
	plan := kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: subjectType, Feature: &kernel.FeatureRegistration{Contributor: owner.Descriptor(), Operation: f.Operation}, Lifecycle: &transition, Capability: proof, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}
	if proof != nil {
		plan.CommandCounters = &kernel.CommandCounterPlan{PolicyVersion: 1, Fingerprint: [32]byte{3}}
	}
	plan, err = coordinator.PrepareCommandPlan(b, command, plan)
	if err != nil {
		t.Fatal("session owner plan", err)
	}
	return coordinator, plan
}

func runAnonymousSessionOwner(t *testing.T, ctx context.Context, c *kernel.Coordinator, command identity.Command, plan kernel.CommandPlan) (identity.CommandResult, error) {
	t.Helper()
	f, _ := command.Feature()
	reservation, result, err := c.ReserveCommand(ctx, f.Binding, command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return result, err
	}
	w, err := c.Begin(ctx, reservation)
	if err != nil {
		return result, err
	}
	defer c.Abort(w, identity.UnavailableError{})
	result, err = c.ApplyFeature(ctx, w, command)
	if err != nil {
		return c.Abort(w, err)
	}
	return c.Commit(w, result)
}

func upgradeSessionRecord(t *testing.T, user identity.UserID, id, family, namespace string, anonymous bool, now time.Time) session.Session {
	t.Helper()
	s, _ := testSession(t).Bindings()
	s.TenantID, s.UserID, s.SessionID, s.FamilyID = "guest-tenant", user, id, family
	s.Version, s.FamilyVersion, s.IssuedAt, s.LastActivityAt = 1, 1, now, now
	s.Lookup = session.TokenDigest{KeyVersion: 1, Sum: sha256.Sum256([]byte(string(user) + "/" + id))}
	s.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationVerified, CredentialID: "password", CredentialVersion: 1, ProofVersion: 1, Proof: authentication.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: string(s.TenantID), Subject: string(user), Method: "password", Assurance: authentication.AssuranceSingleFactor, Purpose: "session-issue", Audience: "service-a", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}}
	if anonymous {
		s.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationAnonymous, AnonymousAt: now}
	}
	keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "guest-deployment", TenantID: s.TenantID}, user)
	sk, _ := SessionAuthorityKeys(s.TenantID, user, family, id)
	pk, _ := (policy.AuthorityScope{TenantID: authorization.TenantID(s.TenantID), PolicyNamespace: namespace, SubjectID: authorization.SubjectID(user)}).Key()
	a := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	var err error
	s.Authority, err = session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: a(keys.Global), Tenant: a(keys.Tenant), User: a(keys.User), Identifier: a(keys.Identifier), Credential: a(keys.Credential), Session: a(sk.Session), SessionFamily: a(sk.Family), Authorization: a(pk)})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(s)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func createUpgradeSessionGuest(t *testing.T, ctx context.Context, pool *database.Pool, repository *kernel.Repository) session.Session {
	t.Helper()
	id, _ := identity.NewSubjectID()
	now := time.Now().UTC().Truncate(time.Microsecond)
	record := upgradeSessionRecord(t, identity.UserID(id), "guest-"+string(id), "guest-family-"+string(id), "guests", true, now)
	s, _ := record.Bindings()
	f, _ := anonymousSessionMappingFixture(t)
	b := f.Binding
	b.CommandID, _ = identity.NewCommandID()
	b.TenantID, b.AnonymousFlowID = s.TenantID, string(b.CommandID)
	creation := b
	creation.UserID, creation.AnonymousFlowID, creation.OperationID, creation.SchemaID = s.UserID, "", "identity.user.create", "guest-profile"
	intent := kernel.AnonymousCreationIntent{Creation: identity.CreateUserCommand{Binding: creation, Status: identity.StatusActive}, Placeholder: identity.Identifier{ID: identity.IdentifierID(id), UserID: s.UserID, Kind: identity.IdentifierAnonymousPlaceholder, CanonicalValue: string(id) + "@anonymous.invalid", Version: 1}}
	fields, err := kernel.AnonymousCreationFields(intent)
	if err != nil {
		t.Fatal(err)
	}
	f.Fields, err = AnonymousSigninSessionFields(record)
	if err != nil {
		t.Fatal(err)
	}
	f.Fields, f.Binding = append(f.Fields, fields...), b
	command, err := identity.NewFeatureCommand(f)
	if err != nil {
		t.Fatal(err)
	}
	domain, _ := kernel.NewAnonymousCreationDomain(repository)
	effect, _ := NewAnonymousSigninEffect(Config{Schema: "session_store", MaximumDuration: time.Second}, AnonymousAdmissionConfig{GlobalAuthorityID: "guest-deployment", PolicyNamespace: "guests", Audience: "service-a"})
	owner := &anonymousSessionFeature{domain: domain, effect: effect, intent: intent, original: command}
	coordinator, plan := anonymousSessionOwnerPlan(t, ctx, pool, repository, owner, command, kernel.LifecyclePlan{EventType: "anonymous.created.v1"}, nil, "")
	result, err := runAnonymousSessionOwner(t, ctx, coordinator, command, plan)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real initial guest creation/session", err, result.Outcome)
	}
	return record
}

func insertUpgradeSessionFixture(t *testing.T, ctx context.Context, pool *database.Pool, record session.Session) {
	t.Helper()
	s, _ := record.Bindings()
	payload, expiry, err := encodeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.families(tenant_id,user_id,family_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4)`, string(s.TenantID), string(s.UserID), s.FamilyID, s.IssuedAt.Format(storedTimeLayout)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.sessions(tenant_id,user_id,session_id,family_id,version,family_version,digest_version,digest,state,expires_at,record) VALUES($1,$2,$3,$4,1,1,1,$5,'active',$6,$7::jsonb)`, string(s.TenantID), string(s.UserID), s.SessionID, s.FamilyID, s.Lookup.Sum[:], expiry, string(payload)); err != nil {
		t.Fatal(err)
	}
}

func TestAnonymousUpgradeSessionAtomicReplacementPreservesTarget(t *testing.T) {
	ctx, pool, repository := anonymousSessionDatabase(t)
	first := createUpgradeSessionGuest(t, ctx, pool, repository)
	// Install real forward suffixes on populated guest/session history.
	base := kernel.DirectoryAuthorityMigrationSource{Base: kernel.AnonymousIdentityMigrationSource{Base: kernel.IdentifierNormalizationMigrationSource{Base: kernel.IdentifierMutationMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}, Version: 14}, Version: 15, GlobalAuthorityID: "guest-deployment", TenantIDs: []identity.TenantID{"guest-tenant"}}
	kernelHistory := kernel.AnonymousUpgradeDisposalMigrationSource{Base: kernel.AnonymousDisposalMigrationSource{Base: base, Version: 25}, Version: 26}
	history, err := kernelHistory.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		if step.Version() > 15 {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("populated kernel disposal history", err)
			}
		}
	}
	for _, source := range []migrations.Source{AnonymousDisposalMigrationSource{Schema: "session_store", Version: 27}, AnonymousUpgradeMigrationSource{AnonymousSignin: AnonymousSigninMigrationSource{Schema: "session_store", Version: 23, Predecessor: AnonymousAfterBaseIssuance}, Version: 28}} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range history {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("populated session upgrade history", err)
			}
		}
	}
	domain, _ := kernel.NewAnonymousDisposalDomain(repository)
	profile := IssueAdmissionConfig{GlobalAuthorityID: "guest-deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	effect, err := NewAnonymousUpgradeEffect(Config{Schema: "session_store", MaximumDuration: time.Second}, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "missing-disposal", "foreign-owner", "native-failure", "audit-failure", "outbox-failure", "final-failure", "late-final", "changed-target", "family-collision"} {
		t.Run(mode, func(t *testing.T) {
			guest := first
			if mode != "commit" {
				guest = createUpgradeSessionGuest(t, ctx, pool, repository)
			}
			g, _ := guest.Bindings()
			for n := 0; n < 17; n++ {
				issuedAt := g.IssuedAt
				if n == 0 {
					issuedAt = issuedAt.Add(-24 * time.Hour)
				}
				record := upgradeSessionRecord(t, g.UserID, fmt.Sprintf("a-sibling-%02d-%s", n, g.UserID), fmt.Sprintf("a-family-%02d-%s", n, g.UserID), "guests", true, issuedAt)
				insertUpgradeSessionFixture(t, ctx, pool, record)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.families(tenant_id,user_id,family_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4)`, string(g.TenantID), string(g.UserID), "empty-family-"+string(g.UserID), g.IssuedAt.Format(storedTimeLayout)); err != nil {
				t.Fatal(err)
			}
			target := identity.UserID("target-" + mode)
			if mode == "commit" {
				target = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',7)`, string(g.TenantID), string(target)); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'password',1,'identity/password',1,true)`, string(g.TenantID), string(target)); err != nil {
				t.Fatal(err)
			}
			if _, err := policy.InitializeAuthority(ctx, pool.Raw(), policy.AuthorityScope{TenantID: authorization.TenantID(g.TenantID), PolicyNamespace: "users", SubjectID: authorization.SubjectID(target)}, time.Second); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			original := upgradeSessionRecord(t, target, "target-source-"+mode, "target-family-"+mode, "users", false, now)
			insertUpgradeSessionFixture(t, ctx, pool, original)
			permanent := upgradeSessionRecord(t, target, "target-successor-"+mode, "successor-family-"+mode, "users", false, now)
			if mode == "family-collision" {
				p, _ := permanent.Bindings()
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.families(tenant_id,user_id,family_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4)`, string(g.TenantID), string(target), p.FamilyID, now.Format(storedTimeLayout)); err != nil {
					t.Fatal(err)
				}
			}
			snapshot, err := repository.GetAnonymousDisposal(ctx, identity.UserStatusQuery{TenantID: g.TenantID, UserID: g.UserID})
			if err != nil {
				t.Fatal(err)
			}
			intent := kernel.AnonymousDisposalIntent{Snapshot: snapshot, Action: kernel.AnonymousDisposeDelete, RetentionPolicyVersion: 1}
			fields, _ := kernel.AnonymousDisposalFields(intent)
			originalFields, _ := OriginalSessionFields(original)
			fields = append(fields, originalFields...)
			commitments, err := AnonymousUpgradeSessionFields(guest, permanent)
			if err != nil {
				t.Fatal(err)
			}
			fields = append(fields, commitments...)
			f, _, _ := anonymousUpgradeSessionFixture(t)
			b := f.Binding
			b.CommandID, _ = identity.NewCommandID()
			b.TenantID, b.UserID, b.ActorID, b.RecordID = g.TenantID, target, identity.ActorID(target), string(g.UserID)
			f.Binding, f.Fields = b, fields
			command, err := identity.NewFeatureCommand(f)
			if err != nil {
				t.Fatal(err)
			}
			until := now.Add(20 * time.Second)
			if mode == "late-final" {
				until = now.Add(500 * time.Millisecond)
			}
			proof := kernel.CapabilityPlan{CapabilityID: string(b.CommandID), Purpose: capability.Purpose(b.OperationID), ReplayKeyVersion: 1, ReplayDigest: [32]byte{1}, ProofFingerprint: [32]byte{2}, ExpiresAt: now.Add(time.Minute).Truncate(time.Second), MaxUses: 1}
			owner := &anonymousUpgradeSessionFeature{domain: domain, effect: effect, intent: intent, command: command, guest: guest, permanent: permanent, until: until, capability: proof, mode: mode}
			transition := kernel.LifecyclePlan{EventType: "anonymous.upgraded.v1", BeforeVersion: 1, AfterVersion: 2}
			coordinator, plan := anonymousSessionOwnerPlan(t, ctx, pool, repository, owner, command, transition, &proof, mode)
			if mode == "changed-target" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET authority_version=2 WHERE tenant_id=$1 AND user_id=$2`, string(g.TenantID), string(target)); err != nil {
					t.Fatal(err)
				}
			}
			result, err := runAnonymousSessionOwner(t, ctx, coordinator, command, plan)
			success := mode == "commit"
			if success && (err != nil || result.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("atomic guest session replacement", err, result.Outcome)
			}
			if !success && result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("invalid replacement committed")
			}
			var guestLive, guestFamilies, targetLive, revoked, issued int
			var targetStatus, targetVersion string
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='active'),(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$3 AND state='active'),(SELECT count(*) FROM session_store.anonymous_disposals WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM session_store.session_issuances WHERE tenant_id=$1 AND user_id=$3 AND purpose='identity.anonymous.upgrade')`, string(g.TenantID), string(g.UserID), string(target)).Scan(&guestLive, &targetLive, &revoked, &issued); err != nil {
				t.Fatal(err)
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT status,version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(g.TenantID), string(target)).Scan(&targetStatus, &targetVersion); err != nil {
				t.Fatal(err)
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.families WHERE tenant_id=$1 AND user_id=$2 AND state='active'`, string(g.TenantID), string(g.UserID)).Scan(&guestFamilies); err != nil {
				t.Fatal(err)
			}
			if targetStatus != "active" || targetVersion != "7" {
				t.Fatal("permanent target was disposed or mutated")
			}
			if success {
				if guestLive != 0 || guestFamilies != 0 || targetLive != 2 || revoked != 1 || issued != 1 {
					t.Fatal("replacement escaped ownership/atomicity", guestLive, guestFamilies, targetLive, revoked, issued)
				}
				got, status, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, b, transition, anonymousUpgradeIssuanceDigest)
				p, _ := permanent.Bindings()
				if err != nil || status != kernel.RecoveryCommitted || got.UserID != target || got.SessionID != p.SessionID || got.FamilyID != p.FamilyID {
					t.Fatal("original permanent issuance evidence lost", err)
				}
				_, replay, err := coordinator.ReserveCommand(ctx, b, command, plan)
				if err != nil || replay.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("exact upgrade replay lost", err)
				}
			} else if guestLive != 18 || guestFamilies != 19 || targetLive != 1 || revoked != 0 || issued != 0 {
				t.Fatal("failed replacement escaped rollback", guestLive, guestFamilies, targetLive, revoked, issued)
			}
			if (mode == "native-failure" || mode == "audit-failure" || mode == "outbox-failure" || mode == "final-failure" || mode == "late-final") && !owner.applied {
				t.Fatal("late denial did not reach both provisional session effects")
			}
		})
	}
}
