package passwordpostgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password/v2"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

type signinMFAChallengePhase struct {
	service      *SigninService
	command      identity.Command
	request      password.SigninRequest
	recipient    kernel.RecipientRecord
	material     password.CredentialSnapshot
	flow         session.PreAuthTransaction
	key          session.DigestKey
	admission    risk.AuthenticationAdmission
	authority    session.AuthoritySnapshotSpec
	primary      mfaSigninPrimary
	continuation mfa.PartialAuthContinuation
	prepared     issuerpg.PreparedIssuance
	upgrade      *kernel.PasswordHashUpgradeIntent
	replacement  primitive.EncodedHash
}

var _ kernel.PasswordMFAChallengeContributor = (*signinMFAChallengePhase)(nil)

func (*signinMFAChallengePhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (*signinMFAChallengePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{signinOperation()}
}
func (p *signinMFAChallengePhase) matches(c identity.Command) bool {
	if p == nil || p.service == nil || p.service.mfa == nil || c != p.command {
		return false
	}
	f, ok := c.PasswordSigninFeature()
	secret, cookie, custody := c.PasswordSigninCustody()
	return ok && custody && secret.Len() > 0 && f.Operation == signinOperation() && cookie.Token() == p.request.Cookie.Token()
}
func (p *signinMFAChallengePhase) scope() (kernel.MFAContinuationPlan, error) {
	s, err := p.continuation.Bindings()
	if err != nil {
		return kernel.MFAContinuationPlan{}, err
	}
	d, err := p.continuation.ScopeDigest()
	if err != nil {
		return kernel.MFAContinuationPlan{}, err
	}
	return kernel.MFAContinuationPlan{ID: identity.CommandID(s.ID), UserID: identity.UserID(s.SubjectID), ScopeDigest: d, PolicyVersion: s.PolicyVersion, FactorVersion: s.FactorVersion, IssuedAt: s.IssuedAt, ExpiresAt: s.ExpiresAt}, nil
}
func (p *signinMFAChallengePhase) ValidatePasswordMFAChallenge(c identity.Command, m kernel.MFAContinuationPlan) error {
	if !p.matches(c) {
		return password.ErrPasswordWork
	}
	expected, err := p.scope()
	if err != nil || m != expected {
		return password.ErrPasswordWork
	}
	return nil
}
func (p *signinMFAChallengePhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if !p.matches(c) || p.recipient.Validate() != nil || p.recipient.Suppressed || plan.SubjectType != "authentication_attempt" || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != signinOperation() || plan.MFAContinuation == nil || plan.Capability != nil || plan.CapabilityIssuance == nil || len(plan.CapabilityIssuance.Grants) != 1 || plan.Lifecycle == nil || plan.Lifecycle.EventType != "mfa.challenge.created.v1" || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 0 || len(plan.Audits) != 1 {
		return password.ErrPasswordWork
	}
	if err := p.ValidatePasswordMFAChallenge(c, *plan.MFAContinuation); err != nil {
		return err
	}
	metadata, err := p.prepared.Plan()
	if err != nil || metadata.MFAContinuationUserID != p.recipient.User.ID || len(metadata.Grants) != 1 || metadata.Grants[0] != plan.CapabilityIssuance.Grants[0] {
		return password.ErrPasswordWork
	}
	f, _ := c.PasswordSigninFeature()
	a := p.admission.Prepared().Scope
	if a.Tenant != string(f.Binding.TenantID) || a.Operation != risk.Action(f.Binding.OperationID) || a.Attempt != string(f.Binding.CommandID) {
		return password.ErrPasswordWork
	}
	wire, _, err := encodeMFASigninPrimary(p.primary)
	if err != nil {
		return err
	}
	defer clear(wire)
	_, _, err = decodeMFASigninPrimary(wire, p.service.c.VerificationKeys, p.service.c.Issuer, p.service.c.Environment, p.primary.Proof.ID, string(f.Binding.TenantID), string(p.recipient.User.ID))
	return err
}
func (s *SigninService) mfaCoordinator(p *signinMFAChallengePhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	l, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.domain, a, l, p, s.mfa.issuer})
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinator(s.pool, registry, s.c.Coordinator)
	return c, registry, err
}
func (p *signinMFAChallengePhase) plan(c *kernel.Coordinator, registry *kernel.ContributorRegistry, now time.Time) (kernel.CommandPlan, error) {
	f, _ := p.command.PasswordSigninFeature()
	b, op := f.Binding, f.Operation
	actor := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		actor = audit.ActorHuman
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: actor, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "authentication_attempt", ID: b.AnonymousFlowID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "authentication_attempt", "aggregate.id": b.AnonymousFlowID, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "authentication_attempt", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	challenge, err := p.scope()
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	issued, err := p.prepared.Plan()
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return c.PrepareCommandPlan(b, p.command, kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, SubjectType: "authentication_attempt", Lifecycle: &kernel.LifecyclePlan{EventType: "mfa.challenge.created.v1"}, MFAContinuation: &challenge, CapabilityIssuance: &issued, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
}
func (p *signinMFAChallengePhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if !p.matches(c) {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.checkTime(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	f, _ := c.PasswordSigninFeature()
	b := f.Binding
	s := p.service
	a := p.authority
	material := p.material.Authority()
	query := kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.c.Profile.GlobalAuthorityID, TenantID: b.TenantID}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{Query: query, GlobalVersion: a.Global.Version, TenantVersion: a.Tenant.Version}); err != nil {
		return identity.FeatureReceipt{}, err
	}
	credential := kernel.CredentialAdmission{Credential: material.Credential, UserAuthorityVersion: p.recipient.UserAuthorityVersion, IdentifierAuthorityVersion: p.recipient.IdentifierAuthorityVersion, CredentialAuthorityVersion: p.recipient.CredentialAuthorityVersion}
	if p.upgrade != nil {
		if err := w.PreparePasswordHashUpgrade(ctx, p, c, p.recipient); err != nil {
			return identity.FeatureReceipt{}, err
		}
	} else if _, err := w.RequireRecipientCredential(ctx, p, p.recipient, credential); err != nil {
		return identity.FeatureReceipt{}, err
	}
	policy := authoritypg.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), SubjectID: authorization.SubjectID(p.recipient.User.ID), PolicyNamespace: s.c.Profile.PolicyNamespace}
	if err := authoritypg.RequireAuthority(ctx, w, policy, a.Authorization.Version, s.c.Repository.MaximumDuration); err != nil {
		return identity.FeatureReceipt{}, err
	}
	scope, _ := p.continuation.Bindings()
	if err := mfapg.RequirePasswordSigninFactorMethods(ctx, w, p, c, p.recipient.User.ID, scope.FactorVersion, scope.AllowedMethods); err != nil {
		return identity.FeatureReceipt{}, err
	}
	lock := " FOR SHARE"
	if p.upgrade != nil {
		lock = " FOR UPDATE"
	}
	rows, err := w.Query(ctx, `SELECT version::text,CASE WHEN octet_length(encoded_hash)<=$4 THEN encoded_hash ELSE '' END FROM identity_password.credentials WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`+lock, string(b.TenantID), string(p.recipient.User.ID), string(material.Credential.ID), int(s.c.Repository.HashPolicy.Limits().EncodedHashBytes))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	var version, hash string
	valid := rows.Next() && rows.Scan(&version, &hash) == nil && !rows.Next() && rows.Err() == nil
	rows.Close()
	if !valid || version != strconv.FormatUint(material.Credential.Version, 10) || hash != p.material.EncodedHash().String() {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if p.upgrade != nil {
		n, err := w.Exec(ctx, `UPDATE identity_password.credentials SET version=version+1,algorithm=$5,encoded_hash=$6,updated_at=GREATEST(updated_at,clock_timestamp()) WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3 AND version=$4::numeric`, string(b.TenantID), string(p.recipient.User.ID), string(material.Credential.ID), version, string(p.replacement.Algorithm()), p.replacement.String())
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if n != 1 {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
		if _, err = w.ApplyPasswordHashUpgrade(ctx, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	bound, fingerprint, generation, err := w.FeatureCommandIdentity(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	use := sessionpg.PreAuthUse{Command: bound, Fingerprint: fingerprint, Generation: generation}
	if generation != 1 {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := sessionpg.ReservePreAuth(ctx, w, s.c.Session, p.flow, use); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := persistMFASigninPrimary(ctx, w, p, c, p.primary, s.c.VerificationKeys, p.continuation); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := s.mfa.issuer.Stage(ctx, w, p.prepared); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := sessionpg.FinalizePreAuth(ctx, w, s.c.Session, p.flow, use); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.checkTime(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: f.Operation}, nil
}
func (p *signinMFAChallengePhase) checkTime(ctx context.Context, w kernel.Work) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return p.checkDelivery(ctx, now)
}
func (p *signinMFAChallengePhase) checkDelivery(ctx context.Context, now time.Time) error {
	if p == nil || ctx == nil {
		return password.ErrPasswordWork
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	f, _ := p.command.PasswordSigninFeature()
	if admitSigninFlow(p.request, p.flow, p.key, f.Binding.PolicyID, f.Binding.PolicyVersion, now) != nil || now.Before(p.primary.Proof.IssuedAt) || !now.Before(p.primary.Proof.ExpiresAt) || !p.material.Authority().ExpiresAt.IsZero() && !now.Before(p.material.Authority().ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return p.admission.CheckAt(ctx, now)
}
func (p *signinMFAChallengePhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if !p.matches(c) {
		return password.ErrPasswordWork
	}
	if err := p.checkTime(ctx, w); err != nil {
		return err
	}
	scope, _ := p.continuation.Bindings()
	return mfapg.RequirePasswordSigninFactorMethods(ctx, w, p, c, p.recipient.User.ID, scope.FactorVersion, scope.AllowedMethods)
}
func (p *signinMFAChallengePhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if p == nil || p.service == nil || ctx == nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	b, _, _, err := w.FeatureScope(p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	m, err := w.PasswordMFAChallenge(p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	cmd, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT p.record,p.record_digest,c.scope_digest FROM identity_password.mfa_primary_records p LEFT JOIN identity_mfa.continuations c ON c.tenant_id=p.tenant_id AND c.origin_purpose=p.purpose AND c.origin_command_id=p.command_id AND c.continuation_id=$3 WHERE p.tenant_id=$1 AND p.command_id=$2 AND p.purpose='identity.password.signin'`, string(b.TenantID), cmd, string(m.ID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, rows.Err()
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var wire, digest, scope []byte
	if rows.Scan(&wire, &digest, &scope) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	defer clear(wire)
	_, sum, err := decodeMFASigninPrimary(wire, p.service.c.VerificationKeys, p.service.c.Issuer, p.service.c.Environment, auth.ProofID(b.CommandID), string(b.TenantID), string(m.UserID))
	if err != nil || len(digest) != 32 || len(scope) != 32 || string(digest) != string(sum[:]) || string(scope) != string(m.ScopeDigest[:]) {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	return kernel.RecoveryCommitted, nil
}
