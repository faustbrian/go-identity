package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password/v2"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// PhonePasswordResetCompletionConfig explicitly enables the consuming half of
// phone recovery. Screening must select the actual phone operation with HIBP;
// its protected provider lane defers velocity only to real completion evidence.
// TOTP borrows the native factor owner, never a caller-supplied accepted verdict.
// AttemptKeyVersion selects a retained SMS attempt codec key. ConfigurationID
// versions borrowed callbacks/policy semantics for original journal restoration.
type PhonePasswordResetCompletionConfig struct {
	ConfigurationID   string
	Screening         password.HashPreparationConfig
	CollectReset      ResetScreeningCollector
	TOTP              *mfapg.PhoneRecoveryTOTPVerifier
	AttemptKeyVersion uint32
}

func (PhonePasswordResetCompletionConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.PhonePasswordResetCompletionConfig(redacted)"))
}
func (PhonePasswordResetCompletionConfig) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}
func (PhonePasswordResetCompletionConfig) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// PhonePasswordResetService composes the genuine native request and complete
// SMS/TOTP recovery journey. It owns no worker, sender, transaction or journal.
// Pools, provider/primitive services and invocation inputs remain caller-owned.
// Independent calls are safe under those dependencies' concurrency contracts.
// HTTP/reference exposure remains separately selected and opt-in.
type PhonePasswordResetService struct {
	read func() *phoneResetCompletionService
}

type phoneResetCompletionService struct {
	request       *PhonePasswordResetRequestService
	native        *phoneResetRequestService
	c             PhonePasswordResetCompletionConfig
	verifier      capability.Service
	configuration [32]byte
}

var _ phone.PasswordResetService = (*PhonePasswordResetService)(nil)

// NewPhonePasswordResetService freezes explicit consuming configuration without
// IO, providers, clocks, password work or migrations. Install the selected kernel,
// canonical password replacement, phone-reset material/session suffixes and
// SMS/TOTP/risk/issuer/audit/outbox histories first. Earlier caller deadlines win
// for every operation. Retain original config and keys for supported recovery.
func NewPhonePasswordResetService(request *PhonePasswordResetRequestService, c PhonePasswordResetCompletionConfig) (*PhonePasswordResetService, error) {
	if request == nil || request.read == nil || !reauthenticationText(c.ConfigurationID, 128) || c.TOTP == nil || c.AttemptKeyVersion == 0 {
		return nil, password.ErrPasswordWork
	}
	n := request.read()
	screening := c.Screening
	if c.CollectReset != nil {
		if screening.Collect != nil {
			return nil, password.ErrPasswordWork
		}
		screening.Collect = func(context.Context, risk.Context, primitive.Secret) ([]risk.Signal, error) {
			return nil, password.ErrPasswordWork
		}
	}
	if _, err := password.NewHashPreparer(screening); err != nil || !signinCurrentHash(c.Screening.DummyHash, n.primary.c.Repository.HashPolicy) {
		return nil, password.ErrPasswordWork
	}
	if _, err := c.Screening.Policy.Admit("identity.phone.password-reset-complete"); err != nil {
		return nil, password.ErrPasswordWork
	}
	hibp, err := c.Screening.Policy.HIBPConfiguration()
	if err != nil || !slices.Contains(hibp.Operations, risk.Action("identity.phone.password-reset-complete")) {
		return nil, password.ErrPasswordWork
	}
	verifier, err := capability.NewService(n.c.Issuer.Crypto)
	if err != nil {
		return nil, err
	}
	if _, err = sessionpg.NewPasswordResetEffect(n.primary.c.Session); err != nil {
		return nil, err
	}
	p := c.Screening.Primitive.Policy()
	frame, err := json.Marshal(struct {
		Domain, Configuration string
		Request               [32]byte
		Minimum, Maximum      uint32
		Timeout               time.Duration
		AttemptVersion        uint32
		Parameters, Limits    any
		Dummy                 [32]byte
		Attributed            bool
	}{"identity-phone-password-reset-complete-v1", c.ConfigurationID, n.profile, c.Screening.MinimumBytes, c.Screening.MaximumBytes, c.Screening.Timeout, c.AttemptKeyVersion, p.Argon2idParameters(), p.Limits(), sha256.Sum256([]byte(c.Screening.DummyHash.String())), c.CollectReset != nil})
	defer clear(frame)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	s := &phoneResetCompletionService{request: request, native: n, c: c, verifier: verifier, configuration: sha256.Sum256(frame)}
	return &PhonePasswordResetService{read: func() *phoneResetCompletionService { return s }}, nil
}

// PasswordResetRequest queues the original native SMS/code and canonical link.
// Commitment is acceptance, not sender delivery. Original keyed retries reuse
// the receipt, including after factor withdrawal; no new risk evaluation runs.
func (s *PhonePasswordResetService) PasswordResetRequest(ctx context.Context, r phone.PasswordResetRequestRequest) (phone.PasswordResetRequestResult, error) {
	if s == nil || s.read == nil {
		return phone.PasswordResetRequestResult{}, password.ErrPasswordWork
	}
	return s.read().request.RequestPasswordReset(ctx, r)
}

func (s *phoneResetCompletionService) coordinator(p *phoneResetCompletionPhase, admitted *phonePasswordRecoveryRisk) (*kernel.Coordinator, error) {
	if s == nil || s.native == nil || p == nil || admitted == nil || admitted.repository == nil {
		return nil, password.ErrPasswordWork
	}
	n := s.native
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, err
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, err
	}
	otp, err := n.c.SMS.NewPhoneRecoveryContributor()
	if err != nil {
		return nil, err
	}
	effect, err := sessionpg.NewPasswordResetEffect(n.primary.c.Session)
	if err != nil {
		return nil, err
	}
	p.service, p.otp, p.sessions, p.risk = s, otp, effect, admitted
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{n.source.directory, audits, outbox, p, otp, admitted.repository, issuerpg.NewParticipant()})
	if err != nil {
		return nil, err
	}
	p.registry = registry
	p.coordinator, err = kernel.NewCoordinator(n.primary.pool, registry, n.primary.c.Coordinator)
	return p.coordinator, err
}

// PasswordResetComplete retains the exact joint password/capability/SMS/TOTP/
// browser input. Canonical issuer provenance selects the account, never a body
// override. HIBP screens before hashing; completion evidence, independent TOTP
// replay, SMS, capability, replacement and all-session revocation commit in the
// sole coordinator Work. Matching retries use original encrypted output and
// plans, not renewed checks or current aggregate versions. No session is issued.
func (s *PhonePasswordResetService) PasswordResetComplete(ctx context.Context, request phone.PasswordResetCompleteRequest) (out phone.PasswordResetCompleteResult, err error) {
	if ctx == nil || s == nil || s.read == nil {
		return out, password.ErrPasswordWork
	}
	r, err := request.Bindings()
	if err != nil {
		return out, err
	}
	native := s.read()
	n := native.native
	ctx, cancel := context.WithTimeout(ctx, n.primary.c.Repository.MaximumDuration)
	defer cancel()
	started := false
	defer func() {
		if recover() != nil {
			out, err = phone.PasswordResetCompleteResult{}, identity.UnavailableError{}
			if started {
				out = phone.PasswordResetCompleteResult{CommandID: r.CommandID, Outcome: identity.CommitOutcomeUnknown}
				err = identity.UnknownCommitError{CommandID: r.CommandID}
			}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	grant, sourceID, replayVersion, err := n.link.issuer.ReadIssuanceOrigin(ctx, n.primary.pool, r.ResetCapability, "identity.phone.password-reset-complete")
	if err != nil {
		return out, err
	}
	origin, err := n.link.profile.ResolveOriginal(grant, time.Now().UTC())
	if err != nil || origin.TenantID != r.TenantID || origin.OriginCommandID != sourceID || r.CommandID == sourceID || r.RiskIssuanceCommandID == sourceID {
		return out, identity.ForbiddenError{}
	}
	admitted, err := newPhonePasswordRecoveryRisk(n.primary.pool, n.c.Risk, r.Caller, origin.UserID)
	if err != nil {
		return out, err
	}
	p := &phoneResetCompletionPhase{origin: origin, grant: grant}
	defer func() { p.custody.Destroy() }()
	coordinator, err := native.coordinator(p, admitted)
	if err != nil {
		return out, err
	}
	caller := r.Caller.Clone()
	caller.Request.Resource.ID = authorization.ResourceID(origin.UserID)
	op := phonePasswordResetOperation()
	q := identity.RecoveryQuery{CommandID: r.CommandID, TenantID: r.TenantID, UserID: origin.UserID, RecordID: string(origin.CredentialID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, OperationID: op.OperationID}
	observed, observeErr := coordinator.ObserveCommandAdmission(ctx, q, caller)
	if observed.Validate() != nil {
		var unavailable identity.UnavailableError
		if !errors.As(observeErr, &unavailable) {
			return out, observeErr
		}
	}
	binding := identity.CommandBinding{CommandID: q.CommandID, TenantID: q.TenantID, UserID: q.UserID, RecordID: q.RecordID, ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: n.primary.c.PolicyID, PolicyVersion: n.primary.c.Coordinator.AdmissionPolicy.PolicyVersion, CorrelationID: string(q.CommandID)}
	var spec identity.FeatureCommandSpec
	if observed.Absent {
		p.source, err = n.restoreIssuedRequest(ctx, origin, r.Caller, r.Flow)
		if err != nil {
			return out, err
		}
		flow, _ := p.source.source.flow.Bindings()
		if flow.Binding.Intent.Origin != r.Origin {
			return out, identity.ForbiddenError{}
		}
		material, err := n.source.passwords.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: r.TenantID, SubjectID: origin.UserID})
		if err != nil {
			return out, err
		}
		a := material.Authority()
		p.intent = kernel.CredentialResetIntent{Replacement: kernel.CredentialReplacementIntent{Credential: a.Credential, ExpectedUserVersion: a.User.Version, ExpectedAuthorityVersion: a.AuthorityVersion}, ExpectedEnabled: a.Enabled}
		fields, err := kernel.CredentialResetFields(p.intent)
		if err != nil {
			return out, err
		}
		factor, err := p.source.prepared.Fields()
		if err != nil {
			return out, err
		}
		intent, err := native.completionIntent(r)
		if err != nil {
			return out, err
		}
		spec = identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: append(append(fields, factor...), intent)}
		p.original, err = native.jointInput(spec, r)
		if err != nil {
			return out, err
		}
		original := phoneResetCompletionOriginalRisk(phone.PasswordResetCompletionRiskRequestSpec{TenantID: r.TenantID, CommandID: r.CommandID, IssuanceCommandID: r.RiskIssuanceCommandID, Caller: r.Caller, Network: r.Network, Device: r.Device}, p.source)
		use, err := admitted.issuer.PrepareUse(ctx, original, risk.EvidenceUseRequest{CommandID: string(r.CommandID), Actor: original.Actor, Recovery: original.Recovery, Reference: r.RiskEvidence})
		if err != nil {
			return out, err
		}
		p.original, p.riskPlan, err = admitted.repository.PreparePhoneResetCompletionEvidenceUse(p.original, original, use)
		if err != nil {
			return out, err
		}
		p.original, p.otpPlan, err = p.source.prepared.PrepareConfirmation(ctx, n.primary.pool, p.original, native.c.AttemptKeyVersion)
		if err != nil {
			return out, err
		}
	} else {
		wire, generation, e := coordinator.QueryFeaturePreparation(ctx, q, caller, kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, p)
		defer clear(wire)
		if e != nil {
			return phone.PasswordResetCompleteResult{CommandID: r.CommandID, Outcome: identity.CommitOutcomeUnknown}, e
		}
		if observed.Validate() == nil {
			binding = observed.Record.Binding
		}
		spec, p.riskPlan, p.otpPlan, err = n.source.passwords.readPhoneResetOutputIntent(ctx, n.crypto, binding, generation, native.configuration, wire)
		if err != nil {
			return out, err
		}
		p.intent, err = passwordResetIntent(spec)
		if err != nil {
			return out, err
		}
		p.original, err = native.jointInput(spec, r)
		if err != nil || p.riskPlan.IssuanceCommandID != string(r.RiskIssuanceCommandID) {
			return out, phone.ErrInvalidPasswordReset
		}
		if observed.Validate() != nil || observed.Record.Outcome == identity.CommitOutcomeInProgress {
			p.source, err = n.restoreIssuedRequest(ctx, origin, r.Caller, r.Flow)
			if err != nil {
				return out, err
			}
		}
	}
	p.consumption, err = n.link.issuer.PreparePhonePasswordResetConsumption(ctx, p.original, replayVersion)
	if err != nil {
		return out, err
	}
	if err = admitted.repository.ValidateRiskEvidenceCommand(p.original, p.riskPlan); err != nil {
		return out, err
	}
	spec, _ = p.original.PhonePasswordResetInputFeature()
	p.declaration, err = resetServiceAuditDeclaration(spec.Binding, op, p.registry.Descriptors(), "credential", p.intent.Replacement.Credential.Version, p.intent.Replacement.Credential.Version+1, origin.IssuedAt)
	if err != nil {
		return out, err
	}
	p.declaration.Capability, p.declaration.OTP, p.declaration.RiskEvidence = &p.consumption, &p.otpPlan, &p.riskPlan
	p.declaration.Lifecycle.EventType = "password.reset.v1"
	plan, err := coordinator.PrepareFeaturePreparationPlan(p.original, p.declaration)
	if err != nil {
		return out, err
	}
	started = true
	result, err := coordinator.ExecutePreparedFeature(ctx, p.original, plan)
	return phoneResetCompleteReceipt(r.CommandID, result, err)
}

// These transport dimensions are not raw joint credential custody, which the
// existing kernel already fingerprints. Keep their original intent beside the
// encrypted native spec so retries cannot silently substitute another evidence
// reference, browser context or provider attribution while reusing old plans.
func (s *phoneResetCompletionService) completionIntent(r phone.PasswordResetCompleteRequestSpec) (identity.FeatureField, error) {
	kind, flowID, _, err := r.Flow.Bindings()
	if err != nil {
		return identity.FeatureField{}, err
	}
	frame, err := json.Marshal(struct {
		Tenant                                  identity.TenantID
		Command, Issuance                       identity.CommandID
		Kind                                    uint8
		Flow, Evidence, Origin, Network, Device string
	}{r.TenantID, r.CommandID, r.RiskIssuanceCommandID, uint8(kind), flowID, r.RiskEvidence.Reveal(), r.Origin, r.Network, r.Device})
	defer clear(frame)
	if err != nil {
		return identity.FeatureField{}, password.ErrPasswordWork
	}
	mac := hmac.New(sha256.New, s.native.c.IntentKey[:])
	mac.Write([]byte("identity-phone-reset-completion-intent-v1\x00"))
	mac.Write(frame)
	return identity.FeatureField{Name: "phone.reset.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: mac.Sum(nil)}}, nil
}

func (s *phoneResetCompletionService) jointInput(spec identity.FeatureCommandSpec, r phone.PasswordResetCompleteRequestSpec) (identity.Command, error) {
	want, err := s.completionIntent(r)
	if err != nil {
		return identity.Command{}, err
	}
	matched := 0
	for _, field := range spec.Fields {
		if field.Name == want.Name {
			if !reflect.DeepEqual(field, want) {
				return identity.Command{}, identity.ConflictError{}
			}
			matched++
		}
	}
	if matched != 1 {
		return identity.Command{}, password.ErrPasswordWork
	}
	command, err := identity.NewFeaturePhonePasswordResetInputCommand(spec, r.NewPassword, r.ResetCapability, r.PhoneCode, r.IndependentTOTP)
	if err != nil {
		return identity.Command{}, err
	}
	_, _, cookie, err := r.Flow.Bindings()
	if err != nil {
		return identity.Command{}, err
	}
	return identity.BindPhonePasswordResetPreAuth(command, cookie)
}

// RecoverPasswordResetRequest reconciles only original authorized scoped request
// history. It accepts no capability/codes and performs no issuance or generation.
func (s *PhonePasswordResetService) RecoverPasswordResetRequest(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (phone.PasswordResetRequestResult, error) {
	if ctx == nil || s == nil || s.read == nil || q.OperationID != phoneResetRequestOperation().OperationID || q.UserID == "" || q.RecordID != string(q.CommandID) {
		return phone.PasswordResetRequestResult{}, password.ErrPasswordWork
	}
	n := s.read().native
	ctx, cancel := context.WithTimeout(ctx, n.primary.c.Repository.MaximumDuration)
	defer cancel()
	trusted := caller.Clone()
	trusted.Request.Resource.ID = ""
	admitted, err := newPhonePasswordRecoveryRisk(n.primary.pool, n.c.Risk, trusted, q.UserID)
	if err != nil {
		return phone.PasswordResetRequestResult{}, err
	}
	phase := &phoneResetRequestPhase{config: n.primary.c, sms: n.c.SMS}
	coordinator, err := n.coordinator(phase, admitted)
	if err != nil {
		return phone.PasswordResetRequestResult{}, err
	}
	result, err := coordinator.RecoverFeatureCommand(ctx, q, caller)
	return phoneResetSendReceipt(q.CommandID, result, err)
}

// RecoverPasswordResetComplete reconciles original material, session, SMS,
// capability and risk participant receipts under current query authorization.
// It performs no factor decryption, credential re-presentation, providers,
// hashing or freshness renewal. Uncertain outcomes remain unknown, not rollback.
func (s *PhonePasswordResetService) RecoverPasswordResetComplete(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (phone.PasswordResetCompleteResult, error) {
	if ctx == nil || s == nil || s.read == nil || q.OperationID != phonePasswordResetOperation().OperationID || q.UserID == "" || q.RecordID == "" {
		return phone.PasswordResetCompleteResult{}, password.ErrPasswordWork
	}
	native := s.read()
	n := native.native
	ctx, cancel := context.WithTimeout(ctx, n.primary.c.Repository.MaximumDuration)
	defer cancel()
	trusted := caller.Clone()
	trusted.Request.Resource.ID = ""
	admitted, err := newPhonePasswordRecoveryRisk(n.primary.pool, n.c.Risk, trusted, q.UserID)
	if err != nil {
		return phone.PasswordResetCompleteResult{}, err
	}
	coordinator, err := native.coordinator(&phoneResetCompletionPhase{}, admitted)
	if err != nil {
		return phone.PasswordResetCompleteResult{}, err
	}
	result, err := coordinator.RecoverFeatureCommand(ctx, q, caller)
	return phoneResetCompleteReceipt(q.CommandID, result, err)
}
