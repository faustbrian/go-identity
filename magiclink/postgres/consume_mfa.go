package magiclinkpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"reflect"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

const consumeMFAPrefix = "MLC3"

type consumeMFAExecution struct {
	continuation mfa.PartialAuthContinuation
	issuance     issuerpg.PreparedIssuance
}

func (e *consumeMFAExecution) plan() (*kernel.MFAContinuationPlan, error) {
	if e == nil {
		return nil, invalid()
	}
	s, err := e.continuation.Bindings()
	if err != nil {
		return nil, err
	}
	digest, err := e.continuation.ScopeDigest()
	if err != nil {
		return nil, err
	}
	return &kernel.MFAContinuationPlan{ID: identity.CommandID(s.ID), UserID: identity.UserID(s.SubjectID), ScopeDigest: digest, PolicyVersion: s.PolicyVersion, FactorVersion: s.FactorVersion, IssuedAt: s.IssuedAt, ExpiresAt: s.ExpiresAt}, nil
}

func (p *consumePhase) ValidateMagicLinkMFAChallenge(c identity.Command, m kernel.MFAContinuationPlan) error {
	if p == nil || !p.mfaRequired || p.service.config.MFA == nil || p.signup != nil || c == (identity.Command{}) || c != p.original && c != p.command {
		return invalid()
	}
	f, _ := p.original.Feature()
	expected := kernel.MFAContinuationPlan{UserID: p.selected.recipient.User.ID, PolicyVersion: f.Binding.PolicyVersion, FactorVersion: p.selected.factor}
	if c == p.original {
		if m != expected {
			return invalid()
		}
		return nil
	}
	if p.execution == nil || p.execution.challenge == nil {
		return invalid()
	}
	complete, err := p.execution.challenge.plan()
	if err != nil || m != *complete {
		return invalid()
	}
	return nil
}

func (p *consumePhase) validateMFAFeature(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.original && c != p.command || plan.Feature == nil || *plan.Feature != p.registration() || plan.SubjectType != "authentication_attempt" || plan.Capability == nil || *plan.Capability != p.proof || plan.MFAContinuation == nil || plan.Lifecycle == nil || plan.Lifecycle.EventType != "mfa.challenge.created.v1" || plan.Lifecycle.BeforeVersion != 0 || plan.Lifecycle.AfterVersion != 0 || plan.MagicLinkRegistration != nil || plan.Delivery != nil || plan.RiskEvidence != nil || plan.CommandCounters != nil || plan.OTP != nil || plan.MFACompletion != nil || len(plan.Audits) != 1 {
		return invalid()
	}
	if c == p.original {
		if plan.CapabilityIssuance != nil {
			return invalid()
		}
	} else {
		if p.execution == nil || p.execution.challenge == nil || plan.CapabilityIssuance == nil {
			return invalid()
		}
		expected, err := p.execution.challenge.issuance.Plan()
		if err != nil || !reflect.DeepEqual(expected, *plan.CapabilityIssuance) {
			return invalid()
		}
	}
	return p.ValidateMagicLinkMFAChallenge(c, *plan.MFAContinuation)
}

// These projections live only in the existing authenticated encrypted output.
// They are neither a new continuation store nor portable permission.
type consumeMFAScope mfa.ContinuationSpec
type consumeMFAOutput struct {
	Schema                        uint8
	Scope                         consumeMFAScope
	Remember                      session.RememberPolicySpec
	Global, Tenant, Authorization uint64
	Issuance                      storedIssuance
	Checkpoint                    []byte
	Admission                     storedAdmission
}

func (a *consumeAdmission) generateMFA(ctx context.Context, generation uint64) ([]byte, error) {
	p := a.owner
	if generation == 0 || p.service.config.MFA == nil || p.authenticatedAt.IsZero() || p.generatedChallengeProof != (capability.Proof{}) {
		return nil, invalid()
	}
	f, _ := p.original.Feature()
	flow, err := p.flow.Bindings()
	if err != nil {
		return nil, err
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return nil, err
	}
	at := p.authenticatedAt.UTC().Truncate(time.Second)
	expires := at.Add(p.service.config.MFA.Lifetime)
	if p.proof.ExpiresAt.Before(expires) {
		expires = p.proof.ExpiresAt
	}
	c, err := mfa.NewPartialAuthContinuation(mfa.ContinuationSpec{ID: mfa.ContinuationID(id), PrimaryProofID: auth.ProofID(p.proof.CapabilityID), PrimaryProofDigest: p.proof.ProofFingerprint, PrimaryProofExpiresAt: p.proof.ExpiresAt, TenantID: f.Binding.TenantID, SubjectID: identity.SubjectID(p.selected.recipient.User.ID), SourcePreAuthID: p.request.PreAuthID, Origin: p.request.Origin, AllowedMethods: []string{"totp"}, PolicyVersion: f.Binding.PolicyVersion, FactorVersion: p.selected.factor, RememberPolicy: flow.Binding.Intent.Remember, Purpose: "identity.mfa.complete", Audience: p.service.request.config().Issuer.Audience, IssuedAt: at, ExpiresAt: expires, MaxAttempts: p.service.config.MFA.MaxAttempts, AttemptsRemaining: p.service.config.MFA.MaxAttempts, State: mfa.Pending, Version: 1})
	if err != nil {
		return nil, err
	}
	payload, err := c.CapabilityPayload(p.service.request.config().IssuerURL)
	if err != nil {
		return nil, err
	}
	prepared, err := p.service.request.issuer.PrepareMFAContinuation(ctx, f.Binding, payload)
	if err != nil {
		return nil, err
	}
	checkpoint, err := p.service.request.codec.CheckpointPreparation(ctx, prepared, generation, func(ctx context.Context, index uint16, raw []byte) error {
		if index != 0 {
			return invalid()
		}
		proof, err := capability.ParseProof(string(raw), capability.DefaultLimits())
		if err != nil {
			return err
		}
		p.generatedChallengeProof = proof
		return ctx.Err()
	})
	if err != nil {
		return nil, err
	}
	plan, err := prepared.Plan()
	if err != nil || len(plan.Grants) != 1 {
		return nil, invalid()
	}
	s, err := c.Bindings()
	if err != nil {
		return nil, err
	}
	remember, err := s.RememberPolicy.Bindings()
	if err != nil {
		return nil, err
	}
	s.RememberPolicy = session.RememberPolicy{}
	stored := consumeMFAOutput{Schema: 3, Scope: consumeMFAScope(s), Remember: remember, Global: p.selected.global, Tenant: p.selected.tenant, Authorization: p.policyVersion, Issuance: storedIssuance{Contributor: plan.Contributor, User: plan.MFAContinuationUserID, Grants: []storedGrant{storedGrant(plan.Grants[0])}}, Checkpoint: checkpoint, Admission: storedAdmission(a.admission.Prepared())}
	plain, err := json.Marshal(stored)
	defer clear(plain)
	if err != nil || len(plain) > maximumRequestOutput-4096 {
		return nil, invalid()
	}
	aad, err := p.consumeAAD(generation)
	if err != nil {
		return nil, err
	}
	sealed, err := p.service.request.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.service.request.config().ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, err
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire)+len(consumeMFAPrefix) > maximumRequestOutput {
		return nil, invalid()
	}
	return append([]byte(consumeMFAPrefix), wire...), nil
}

func (p *consumePhase) restoreMFAOutput(ctx context.Context, generation uint64, wire []byte) (*consumeExecution, identity.Command, error) {
	deny := func() (*consumeExecution, identity.Command, error) { return nil, identity.Command{}, invalid() }
	if !p.mfaRequired || len(wire) <= len(consumeMFAPrefix) || len(wire) > maximumRequestOutput || string(wire[:len(consumeMFAPrefix)]) != consumeMFAPrefix {
		return deny()
	}
	aad, err := p.consumeAAD(generation)
	if err != nil {
		return deny()
	}
	sealed, err := envelope.ParseEnvelope(wire[len(consumeMFAPrefix):])
	if err != nil {
		return deny()
	}
	plain, err := p.service.request.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > maximumRequestOutput-4096 {
		return deny()
	}
	var stored consumeMFAOutput
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&stored) != nil || decoder.Decode(new(any)) != io.EOF || stored.Schema != 3 || len(stored.Issuance.Grants) != 1 || stored.Global == 0 || stored.Tenant == 0 || stored.Authorization == 0 {
		return deny()
	}
	canonical, err := json.Marshal(stored)
	defer clear(canonical)
	if err != nil || !bytes.Equal(plain, canonical) {
		return deny()
	}
	s := mfa.ContinuationSpec(stored.Scope)
	s.RememberPolicy, err = session.NewRememberPolicy(stored.Remember)
	if err != nil {
		return deny()
	}
	c, err := mfa.NewPartialAuthContinuation(s)
	if err != nil {
		return deny()
	}
	f, _ := p.original.Feature()
	flow, err := p.flow.Bindings()
	if err != nil {
		return deny()
	}
	originalRemember, err := flow.Binding.Intent.Remember.Bindings()
	if err != nil || originalRemember != stored.Remember || s.State != mfa.Pending || s.Version != 1 || s.AttemptsRemaining != s.MaxAttempts || s.MaxAttempts != p.service.config.MFA.MaxAttempts || s.TenantID != f.Binding.TenantID || s.SubjectID != identity.SubjectID(p.selected.recipient.User.ID) || s.SourcePreAuthID != p.request.PreAuthID || s.Origin != p.request.Origin || string(s.PrimaryProofID) != p.proof.CapabilityID || s.PrimaryProofDigest != p.proof.ProofFingerprint || !s.PrimaryProofExpiresAt.Equal(p.proof.ExpiresAt) || s.PolicyVersion != f.Binding.PolicyVersion || s.FactorVersion != p.selected.factor || s.Purpose != "identity.mfa.complete" || s.Audience != p.service.request.config().Issuer.Audience || !reflect.DeepEqual(s.AllowedMethods, []string{"totp"}) || s.ExpiresAt.Sub(s.IssuedAt) > p.service.config.MFA.Lifetime || s.IssuedAt.Before(p.grant.Payload().IssuedAt) {
		return deny()
	}
	plan := kernel.CapabilityIssuancePlan{Contributor: stored.Issuance.Contributor, MFAContinuationUserID: stored.Issuance.User, Grants: []kernel.CapabilityPlan{kernel.CapabilityPlan(stored.Issuance.Grants[0])}}
	if plan.MFAContinuationUserID != p.selected.recipient.User.ID || plan.Grants[0].CapabilityID != string(s.ID) || plan.Grants[0].Purpose != "identity.mfa.complete" || !plan.Grants[0].ExpiresAt.Equal(s.ExpiresAt) {
		return deny()
	}
	prepared, err := p.service.request.codec.RestorePreparation(ctx, f.Binding, generation, plan, stored.Checkpoint)
	if err != nil {
		return deny()
	}
	scope := risk.Context{Tenant: string(f.Binding.TenantID), Operation: risk.Action(f.Binding.OperationID), Attempt: string(f.Binding.CommandID)}
	a, err := p.service.request.custody.Restore(ctx, risk.PreparedAuthenticationAdmission(stored.Admission), scope, p.subject)
	if err != nil {
		return deny()
	}
	p.selected.global, p.selected.tenant, p.policyVersion = stored.Global, stored.Tenant, stored.Authorization
	generated := f
	generated.Fields = append(generated.Fields, identity.FeatureField{Name: "mfa.challenge-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(s.ID)}})
	command, err := identity.NewFeaturePreAuthCommand(generated, p.request.Cookie)
	if err != nil {
		return deny()
	}
	return &consumeExecution{challenge: &consumeMFAExecution{continuation: c, issuance: prepared}, admission: a, generation: generation, digest: sha256.Sum256(wire)}, command, nil
}

func (p *consumePhase) checkMFA(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.execution == nil || p.execution.challenge == nil || c != p.command {
		return invalid()
	}
	if err := mfapg.RequireMagicLinkTOTPChallenge(ctx, w, p, c, p.selected.recipient.User.ID, p.selected.factor); err != nil {
		return err
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.service.request.config().GlobalAuthorityID, TenantID: p.request.TenantID}, GlobalVersion: p.selected.global, TenantVersion: p.selected.tenant}); err != nil {
		return err
	}
	if err := w.RequireRecipient(ctx, p, p.selected.recipient); err != nil {
		return err
	}
	if err := authoritypg.RequireAuthority(ctx, w, authoritypg.AuthorityScope{TenantID: authorization.TenantID(p.request.TenantID), SubjectID: authorization.SubjectID(p.selected.recipient.User.ID), PolicyNamespace: p.service.config.PolicyNamespace}, p.policyVersion, p.service.request.config().MaximumDuration); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err := p.execution.admission.CheckAt(ctx, now); err != nil {
		return err
	}
	if err := p.execution.challenge.continuation.RequirePending(now); err != nil {
		return err
	}
	if _, err := p.service.request.validateConsumptionScope(p.request, p.flow, p.grant, p.origin, p.selected.recipient, now); err != nil {
		return err
	}
	return p.service.request.admitFlow(p.flowInput(), p.flow, now)
}

func (p *consumePhase) applyMFA(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := p.checkMFA(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := mfapg.PersistMagicLinkContinuation(ctx, w, p, c, p.execution.challenge.continuation); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.request.issuer.Stage(ctx, w, p.execution.challenge.issuance); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, fp, generation, err := w.FeatureCommandIdentity(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	use := sessionpg.PreAuthUse{Command: b, Fingerprint: fp, Generation: generation}
	if err := sessionpg.ReservePreAuth(ctx, w, p.service.request.config().Session, p.flow, use); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := sessionpg.FinalizePreAuth(ctx, w, p.service.request.config().Session, p.flow, use); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: consumeOperation()}, nil
}
