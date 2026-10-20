package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	"github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// One synchronous coordinator invocation owns this state. The OTP contributor
// retains its own counted/consuming factor custody; this phase cannot substitute
// a successful classification for the actual consuming TOTP verification/CAS.
type phoneResetCompletionPhase struct {
	service             *phoneResetCompletionService
	coordinator         *kernel.Coordinator
	registry            *kernel.ContributorRegistry
	original, generated identity.Command
	intent              kernel.CredentialResetIntent
	origin              password.ResetGrantSpec
	grant               capability.Grant
	consumption         kernel.CapabilityPlan
	source              *phoneResetIssuedRequest
	risk                *phonePasswordRecoveryRisk
	riskPlan            kernel.RiskEvidencePlan
	otp                 *otppg.Contributor
	otpPlan             kernel.OTPAttemptPlan
	custody             otppg.PhoneRecoveryCustody
	sessions            *sessionpg.PasswordResetEffect
	declaration         kernel.CommandPlan
	facts               []risk.Signal
	generation          uint64
	output              [32]byte
}

var _ kernel.CredentialResetContributor = (*phoneResetCompletionPhase)(nil)
var _ kernel.FeatureAdmissionPreparationContributor = (*phoneResetCompletionPhase)(nil)
var _ kernel.FeatureCommitContributor = (*phoneResetCompletionPhase)(nil)

func (*phoneResetCompletionPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (*phoneResetCompletionPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{phonePasswordResetOperation()}
}

func (p *phoneResetCompletionPhase) CredentialReset(c identity.Command) (kernel.CredentialResetIntent, error) {
	if p == nil || p.service == nil || c == (identity.Command{}) || c != p.generated {
		return kernel.CredentialResetIntent{}, password.ErrPasswordWork
	}
	i, _, err := passwordResetOriginalMaterial(c, p.service.native.source.passwords.policy, p.service.native.link.profile, p.origin, p.grant, p.consumption, p.origin.IssuedAt)
	if err != nil || i != p.intent {
		return kernel.CredentialResetIntent{}, password.ErrPasswordWork
	}
	return i, nil
}

func (p *phoneResetCompletionPhase) validatePlan(plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || p.risk == nil || plan.Feature == nil || *plan.Feature != (kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: phonePasswordResetOperation()}) || plan.SubjectType != "credential" || plan.Capability == nil || *plan.Capability != p.consumption || plan.OTP == nil || *plan.OTP != p.otpPlan || plan.RiskEvidence == nil || *plan.RiskEvidence != p.riskPlan || plan.CommandCounters != nil || plan.CaptchaEvidence != nil || plan.Delivery != nil || plan.CapabilityIssuance != nil || plan.Lifecycle == nil || *plan.Lifecycle != (kernel.LifecyclePlan{EventType: "password.reset.v1", BeforeVersion: p.intent.Replacement.Credential.Version, AfterVersion: p.intent.Replacement.Credential.Version + 1}) || len(plan.Audits) != 1 {
		return password.ErrPasswordWork
	}
	a := plan.Audits[0]
	if a.EventType != phonePasswordResetOperation().OperationID || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" {
		return password.ErrPasswordWork
	}
	return nil
}

func (p *phoneResetCompletionPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	if err := p.validatePlan(plan); err != nil {
		return err
	}
	spec, ok := c.PhonePasswordResetInputFeature()
	i, err := passwordResetIntent(spec)
	if !ok || c != p.original || err != nil || i != p.intent {
		return password.ErrPasswordWork
	}
	if err := passwordResetOriginalIntent(i, p.service.native.link.profile, p.origin, p.grant, p.consumption, p.origin.IssuedAt); err != nil {
		return err
	}
	return p.risk.repository.ValidateRiskEvidenceCommand(c, p.riskPlan)
}

func (p *phoneResetCompletionPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if err := p.validatePlan(plan); err != nil {
		return err
	}
	if _, err := p.CredentialReset(c); err != nil {
		return err
	}
	return p.risk.repository.ValidateRiskEvidenceCommand(c, p.riskPlan)
}

func (p *phoneResetCompletionPhase) current(ctx context.Context, w kernel.Work, successor bool) error {
	if p == nil || p.service == nil || p.source == nil {
		return identity.ForbiddenError{}
	}
	s := p.source.source
	recipient := p.source.recipient
	if recipient.Validate() != nil || recipient.Suppressed || recipient.Query.UserID != p.origin.UserID || recipient.User.ID != p.origin.UserID || recipient.Identifier.ID != p.origin.IdentifierID || recipient.Identifier.Version != p.origin.IdentifierVersion || recipient.Verification.Version != p.origin.Phone.VerificationVersion || recipient.UserAuthorityVersion != p.origin.UserAuthorityVersion || recipient.CredentialAuthorityVersion != p.origin.CredentialAuthorityVersion {
		return identity.ForbiddenError{}
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, s.directory); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, p, s.policy); err != nil {
		return err
	}
	if successor {
		recipient.CredentialAuthorityVersion++
	}
	return w.RequireRecipient(ctx, p, recipient)
}

func (p *phoneResetCompletionPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || c == (identity.Command{}) || c != p.original && c != p.generated {
		return password.ErrPasswordWork
	}
	if err := p.current(ctx, w, false); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(ctx, p, p.source.source.credential); err != nil {
		return err
	}
	if c == p.original {
		return sessionpg.RequirePreAuth(ctx, w, p.service.native.primary.c.Session, p.source.source.flow)
	}
	// reserveOTP repeats input admission after ReserveOTP changes issued to
	// reserved. The OTP owner authenticates the exact original browser before
	// counted comparison/reservation, then its command/fingerprint/generation
	// during CheckOTP/FinalizeOTP. An issued-only read here would reject our own
	// reservation. Only that owner's exact retained generated command reaches
	// this branch; all primary/current-credential fences above still apply.
	return nil
}

type phoneResetCompleteAdmission struct{ phase *phoneResetCompletionPhase }

func (a phoneResetCompleteAdmission) Check(ctx context.Context) error {
	if ctx == nil || a.phase == nil || a.phase.service == nil {
		return password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p := a.phase
	now := time.Now().UTC()
	if !now.Before(p.riskPlan.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return p.service.native.link.profile.Authorize(p.grant, p.origin, now)
}
func (a phoneResetCompleteAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a.phase.GenerateFeaturePreparation(ctx, a.phase.original, generation)
}
func (p *phoneResetCompletionPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.original || p.risk.repository.ValidateRiskEvidenceCommand(c, p.riskPlan) != nil {
		return nil, password.ErrPasswordWork
	}
	a := phoneResetCompleteAdmission{p}
	return a, a.Check(ctx)
}
func (p *phoneResetCompletionPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if c != p.original {
		return nil, password.ErrPasswordWork
	}
	_, _, riskPlan, otpPlan, err := p.service.native.source.passwords.restorePhoneResetOutput(ctx, p.service.native.crypto, c, generation, p.service.configuration, wire)
	if err != nil || riskPlan != p.riskPlan || otpPlan != p.otpPlan {
		return nil, password.ErrPasswordWork
	}
	return p.PrepareFeatureAdmission(ctx, c)
}

func (p *phoneResetCompletionPhase) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	if c != p.original || generation == 0 {
		return nil, password.ErrPasswordWork
	}
	s, n := p.service, p.service.native
	command, facts, err := n.source.passwords.generatePhoneResetCommand(ctx, c, s.c.Screening, s.verifier, n.link.profile, p.origin, p.grant, p.consumption, s.c.CollectReset)
	if err != nil {
		return nil, err
	}
	if err = (phoneResetCompleteAdmission{p}).Check(ctx); err != nil {
		return nil, err
	}
	return n.source.passwords.sealPhoneResetOutput(ctx, n.crypto, n.c.ActiveEnvelopeKeyID, c, generation, s.configuration, command, facts, p.riskPlan, p.otpPlan)
}

func (p *phoneResetCompletionPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	bad := func(err error) (identity.Command, kernel.CommandPlan, error) {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	if c != p.original || p.source == nil || p.otp == nil {
		return bad(password.ErrPasswordWork)
	}
	s, n := p.service, p.service.native
	command, facts, riskPlan, otpPlan, err := n.source.passwords.restorePhoneResetOutput(ctx, n.crypto, c, generation, s.configuration, wire)
	if err != nil || riskPlan != p.riskPlan || otpPlan != p.otpPlan {
		return bad(password.ErrPasswordWork)
	}
	if _, _, err = passwordResetOriginalMaterial(command, n.source.passwords.policy, n.link.profile, p.origin, p.grant, p.consumption, time.Now().UTC()); err != nil {
		return bad(err)
	}
	if err = p.risk.repository.ValidateRiskEvidenceCommand(command, p.riskPlan); err != nil {
		return bad(err)
	}
	factor, err := p.source.prepared.OriginalFactor()
	if err != nil {
		return bad(err)
	}
	_, smsExpiry, err := p.source.prepared.Timeline()
	if err != nil {
		return bad(err)
	}
	until := p.origin.ExpiresAt
	for _, expiry := range []time.Time{p.riskPlan.ExpiresAt, smsExpiry} {
		if expiry.Before(until) {
			until = expiry
		}
	}
	p.custody, err = p.otp.PreparePhoneRecovery(ctx, command, p.otpPlan, otppg.PhoneRecoveryPreparation{Factor: factor, Verifier: s.c.TOTP, ValidUntil: until})
	if err != nil {
		return bad(err)
	}
	p.generated, p.facts, p.generation, p.output = command, facts, generation, sha256.Sum256(wire)
	// Generic PrepareCommandPlan deliberately rejects all joint phone custody.
	// ExecutePreparedFeature alone validates the returned declaration through
	// its closed prepareRestoredFeature/prepareOTPReservation route, retaining
	// every consuming owner rather than bypassing that boundary.
	return command, p.declaration, nil
}

func (p *phoneResetCompletionPhase) checkTime(ctx context.Context, w kernel.Work) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if !now.Before(p.riskPlan.ExpiresAt) || p.service.native.link.profile.Authorize(p.grant, p.origin, now) != nil {
		return identity.ForbiddenError{}
	}
	spec, ok := p.generated.PhonePasswordResetFeature()
	if !ok {
		return password.ErrPasswordWork
	}
	b := spec.Binding
	a, err := p.service.c.Screening.Policy.AssessProtectedProviders(ctx, risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID), Now: now}, p.facts)
	if err != nil || a.Decision.Action != risk.Allow {
		return password.ErrPasswordWork
	}
	return nil
}

func (p *phoneResetCompletionPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	bad := func(err error) (identity.FeatureReceipt, error) { return identity.FeatureReceipt{}, err }
	if p == nil || c != p.generated || p.generation == 0 {
		return bad(password.ErrPasswordWork)
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return bad(err)
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	digest := sha256.Sum256(wire)
	clear(wire)
	if err != nil || generation != p.generation || digest != p.output {
		return bad(password.ErrPasswordWork)
	}
	if err := p.current(ctx, w, false); err != nil {
		return bad(err)
	}
	if err := p.checkTime(ctx, w); err != nil {
		return bad(err)
	}
	completion, err := p.custody.VerifyAndRecordTOTP(ctx, w, p)
	if err != nil {
		return bad(err)
	}
	if err := completion.RequireRecorded(ctx, w, p, c); err != nil {
		return bad(err)
	}
	receipt, err := p.service.native.source.passwords.applyResetMaterial(ctx, w, p, c)
	if err != nil {
		return bad(err)
	}
	if _, err = p.sessions.Apply(ctx, w, p, c); err != nil {
		return bad(err)
	}
	if err = p.checkTime(ctx, w); err != nil {
		return bad(err)
	}
	return receipt, nil
}

func (p *phoneResetCompletionPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || c != p.generated {
		return password.ErrPasswordWork
	}
	if err := p.current(ctx, w, true); err != nil {
		return err
	}
	return p.checkTime(ctx, w)
}
func (p *phoneResetCompletionPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if p == nil || p.service == nil || p.sessions == nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	material, err := p.service.native.source.passwords.recoverReplacement(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	sessions, err := p.sessions.Recover(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	if material != sessions {
		return kernel.RecoveryUnknown, nil
	}
	return material, nil
}
