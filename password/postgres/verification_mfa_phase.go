package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"reflect"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

type verificationMFAInput struct {
	binding      identity.CommandBinding
	request      email.VerificationSigninRequest
	origin       email.RegistrationVerificationSpec
	flow         session.PreAuthTransaction
	primary      capability.Grant
	recipient    kernel.RecipientRecord
	confirmation identity.CommandResult
	factor       uint64
	admission    risk.AuthenticationAdmission
	subject      risk.Subject
	authority    session.AuthoritySnapshot
	at           time.Time
}

func newVerificationMFAComposition(c MFAChallengeConfig, audience string) (*signinMFAComposition, error) {
	methods, err := freezeMFACompletionMethods(c.AllowedMethods)
	u, urlErr := url.Parse(c.IssuerURL)
	if err != nil || urlErr != nil || !reflect.DeepEqual(methods, []string{"totp"}) || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || c.Lifetime < time.Second || c.Lifetime > 5*time.Minute || c.Lifetime%time.Second != 0 || c.MaxAttempts < 1 || c.MaxAttempts > 100 || c.Issuer.Audience != audience || c.Issuer.Crypto.Issuer != c.IssuerURL {
		return nil, email.ErrInvalidVerification
	}
	i, err := issuerpg.NewIssuer(c.Issuer)
	if err != nil {
		return nil, err
	}
	codec, err := issuerpg.NewIssuancePreparationCodec(i, c.Custody)
	if err != nil {
		return nil, err
	}
	return &signinMFAComposition{issuer: i, codec: codec, config: MFAChallengeConfig{AllowedMethods: methods, Lifetime: c.Lifetime, MaxAttempts: c.MaxAttempts, IssuerURL: c.IssuerURL}}, nil
}

type verificationMFAChallengePhase struct {
	service           *VerificationSigninService
	input             verificationMFAInput
	original, command identity.Command
	intent            [32]byte
	coordinator       *kernel.Coordinator
	registry          *kernel.ContributorRegistry
	continuation      mfa.PartialAuthContinuation
	prepared          issuerpg.PreparedIssuance
	proof             capability.Proof
	outputDigest      [32]byte
	outputGeneration  uint64
}

var _ kernel.FeaturePreparationContributor = (*verificationMFAChallengePhase)(nil)
var _ kernel.EmailVerificationMFAChallengeContributor = (*verificationMFAChallengePhase)(nil)

func (*verificationMFAChallengePhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}
}
func (*verificationMFAChallengePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{verificationSigninOperation()}
}
func (p *verificationMFAChallengePhase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: verificationSigninOperation()}
}

func (s *VerificationSigninService) mfaCoordinator(p *verificationMFAChallengePhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	l, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	r, err := kernel.NewContributorRegistry([]kernel.Contributor{s.signup.directory, a, l, p, s.mfa.issuer})
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinator(s.signup.pool, r, s.signup.config().Coordinator)
	return c, r, err
}

func (s *VerificationSigninService) challengeVerification(ctx context.Context, input verificationMFAInput, out email.VerificationSigninResult) (email.VerificationSigninResult, error) {
	p := &verificationMFAChallengePhase{service: s, input: input}
	flow, err := signupFlowProjection(input.flow)
	if err != nil {
		return out, err
	}
	authority, _ := input.authority.Bindings()
	frame, err := json.Marshal(struct {
		Primary   verificationStoredPayload
		Flow      signupOriginalFlow
		Factor    uint64
		Authority session.AuthoritySnapshotSpec
		At        time.Time
	}{verificationStoredPayload(input.primary.Payload()), flow, input.factor, authority, input.at})
	if err != nil {
		return out, err
	}
	p.intent = sha256.Sum256(frame)
	clear(frame)
	p.original, err = identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: input.binding, Operation: verificationSigninOperation(), Fields: []identity.FeatureField{{Name: "verification.mfa.intent", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: hex.EncodeToString(p.intent[:])}}}}, input.request.Browser)
	if err != nil {
		return out, err
	}
	p.coordinator, p.registry, err = s.mfaCoordinator(p)
	if err != nil {
		return out, err
	}
	raw, err := p.plan(false)
	if err != nil {
		return out, err
	}
	declaration, err := p.coordinator.PrepareFeaturePreparationPlan(p.original, raw)
	if err != nil {
		return out, err
	}
	receipt, err := p.coordinator.ExecutePreparedFeature(ctx, p.original, declaration)
	if receipt.Outcome != identity.CommitOutcomeInvalid {
		out.Issuance.CommitOutcome, out.Issuance.RetryAfter = receipt.Outcome, receipt.RetryAfter
	}
	if receipt.Outcome == identity.CommitOutcomeCommitted {
		scope, scopeErr := p.continuation.Bindings()
		if scopeErr != nil {
			return out, identity.UnavailableError{}
		}
		out.Issuance.Replayed = p.proof == (capability.Proof{})
		out.Challenge = &email.VerificationMFAChallenge{ID: identity.CommandID(scope.ID), Method: "totp", ExpiresAt: scope.ExpiresAt}
		if err == nil && !out.Issuance.Replayed {
			if err = p.checkTime(ctx, s.c.Issuance.Clock.Now()); err == nil {
				out.Challenge.Proof = p.proof
			}
		}
	}
	return out, err
}

func (p *verificationMFAChallengePhase) scope() (kernel.MFAContinuationPlan, error) {
	if p.command == (identity.Command{}) {
		return kernel.MFAContinuationPlan{UserID: p.input.binding.UserID, PolicyVersion: p.input.binding.PolicyVersion, FactorVersion: p.input.factor}, nil
	}
	s, err := p.continuation.Bindings()
	if err != nil {
		return kernel.MFAContinuationPlan{}, err
	}
	digest, err := p.continuation.ScopeDigest()
	return kernel.MFAContinuationPlan{ID: identity.CommandID(s.ID), UserID: identity.UserID(s.SubjectID), PolicyVersion: s.PolicyVersion, FactorVersion: s.FactorVersion, ScopeDigest: digest, IssuedAt: s.IssuedAt, ExpiresAt: s.ExpiresAt}, err
}

func (p *verificationMFAChallengePhase) ValidateEmailVerificationMFAChallenge(c identity.Command, m kernel.MFAContinuationPlan) error {
	if p == nil || p.service == nil || c != (p.original) && c != (p.command) {
		return email.ErrInvalidVerification
	}
	expected := kernel.MFAContinuationPlan{UserID: p.input.binding.UserID, PolicyVersion: p.input.binding.PolicyVersion, FactorVersion: p.input.factor}
	if c == p.command && c != (identity.Command{}) {
		var err error
		expected, err = p.scope()
		if err != nil {
			return err
		}
	}
	if m != expected {
		return email.ErrInvalidVerification
	}
	return nil
}
func (p *verificationMFAChallengePhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || c == (identity.Command{}) || c != p.original && c != p.command || plan.Feature == nil || *plan.Feature != p.registration() || plan.SubjectType != "authentication_attempt" || plan.Lifecycle == nil || *plan.Lifecycle != (kernel.LifecyclePlan{EventType: "mfa.challenge.created.v1", AfterVersion: 1}) || plan.MFAContinuation == nil || plan.Capability != nil || plan.MFACompletion != nil || plan.Delivery != nil || plan.OTP != nil || plan.CommandCounters != nil || plan.RiskEvidence != nil || len(plan.Audits) != 1 {
		return email.ErrInvalidVerification
	}
	if err := p.ValidateEmailVerificationMFAChallenge(c, *plan.MFAContinuation); err != nil {
		return err
	}
	if c == p.original {
		if plan.CapabilityIssuance != nil {
			return email.ErrInvalidVerification
		}
		return nil
	}
	metadata, err := p.prepared.Plan()
	if err != nil || plan.CapabilityIssuance == nil || !reflect.DeepEqual(metadata, *plan.CapabilityIssuance) {
		return email.ErrInvalidVerification
	}
	return nil
}
func (p *verificationMFAChallengePhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}

func (p *verificationMFAChallengePhase) plan(generated bool) (kernel.CommandPlan, error) {
	b := p.input.binding
	actor := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		actor = audit.ActorHuman
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: p.input.at, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: actor, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "authentication_attempt", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "authentication_attempt", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, verificationSigninOperation(), "authentication_attempt", seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	scope, err := p.scope()
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	contributors := p.registry.Descriptors()
	plan := kernel.CommandPlan{Contributors: contributors[:len(contributors)-1], Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: verificationSigninOperation()}, SubjectType: "authentication_attempt", Lifecycle: &kernel.LifecyclePlan{EventType: "mfa.challenge.created.v1", AfterVersion: 1}, MFAContinuation: &scope, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}
	if generated {
		metadata, err := p.prepared.Plan()
		if err != nil {
			return kernel.CommandPlan{}, err
		}
		plan.Contributors = contributors
		plan.CapabilityIssuance = &metadata
	}
	return plan, nil
}

func (p *verificationMFAChallengePhase) checkTime(ctx context.Context, at time.Time) error {
	if err := p.service.originalBrowser(p.input.request, p.input.origin, p.input.flow, at); err != nil {
		return err
	}
	if at.Before(p.input.at) || !at.Before(p.input.primary.Payload().ExpiresAt) {
		return identity.ForbiddenError{}
	}
	if err := p.input.admission.CheckAt(ctx, at); err != nil {
		return err
	}
	if _, err := p.continuation.Bindings(); err == nil {
		return p.continuation.RequirePending(at)
	}
	return nil
}
func (p *verificationMFAChallengePhase) checkCurrent(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || p.service == nil || c != p.original && c != p.command {
		return email.ErrInvalidVerification
	}
	at, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err = p.checkTime(ctx, at); err != nil {
		return err
	}
	a, _ := p.input.authority.Bindings()
	cfg := p.service.signup.config()
	b := p.input.binding
	if err := w.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.service.c.Profile.GlobalAuthorityID, TenantID: b.TenantID}, GlobalVersion: a.Global.Version, TenantVersion: a.Tenant.Version}); err != nil {
		return err
	}
	if err := w.RequireRecipient(ctx, p, p.input.recipient); err != nil {
		return err
	}
	if err := authoritypg.RequireAuthority(ctx, w, authoritypg.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), SubjectID: authorization.SubjectID(b.UserID), PolicyNamespace: p.service.c.Profile.PolicyNamespace}, a.Authorization.Version, cfg.Repository.MaximumDuration); err != nil {
		return err
	}
	if err := mfapg.RequireEmailVerificationTOTPChallenge(ctx, w, p, c, p.input.factor); err != nil {
		return err
	}
	if err := sessionpg.RequireVerificationSignupPreAuth(ctx, w, p, c, cfg.Session, p.input.flow, p.input.origin.Binding.CommandID); err != nil {
		return err
	}
	return p.service.mfa.issuer.RequireVerificationMFAParent(ctx, w, p, p.input.primary, p.input.origin.Binding.CommandID)
}
func (p *verificationMFAChallengePhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.checkCurrent(ctx, w, c)
}
func (p *verificationMFAChallengePhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.checkCurrent(ctx, w, c)
}
func (p *verificationMFAChallengePhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if c != p.command || p.outputGeneration == 0 {
		return identity.FeatureReceipt{}, email.ErrInvalidVerification
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	digest := sha256.Sum256(wire)
	clear(wire)
	if generation != p.outputGeneration || digest != p.outputDigest {
		return identity.FeatureReceipt{}, email.ErrInvalidVerification
	}
	if err := p.checkCurrent(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := mfapg.PersistEmailVerificationContinuation(ctx, w, p, c, p.continuation); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.mfa.issuer.Stage(ctx, w, p.prepared); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: verificationSigninOperation(), AfterVersion: 1}, nil
}
func (p *verificationMFAChallengePhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, _, _, err := w.FeatureScope(p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	m, err := w.EmailVerificationMFAChallenge(p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	cmd, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	rows, err := w.Query(ctx, `SELECT user_id,scope_digest FROM identity_mfa.continuations WHERE tenant_id=$1 AND origin_purpose='identity.email.verification-signin' AND origin_command_id=$2 AND continuation_id=$3`, string(b.TenantID), cmd, string(m.ID))
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
	var user string
	var digest []byte
	if rows.Scan(&user, &digest) != nil || rows.Next() || rows.Err() != nil || user != string(m.UserID) || len(digest) != 32 || !reflect.DeepEqual(digest, m.ScopeDigest[:]) {
		return kernel.RecoveryUnknown, email.ErrInvalidVerification
	}
	return kernel.RecoveryCommitted, nil
}
