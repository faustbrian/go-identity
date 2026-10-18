package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"reflect"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// These projections exist only inside authenticated encrypted journal output.
// They are original custody, not another primary proof or a renewable lease.
type verificationStoredPayload capability.Payload
type verificationStoredScope mfa.ContinuationSpec
type verificationMFAOutput struct {
	Schema          uint8
	Intent          [32]byte
	Scope           verificationStoredScope
	Flow            signupOriginalFlow
	Primary         verificationStoredPayload
	PrimaryEnvelope [32]byte
	Metadata        session.MagicLinkAuthenticationSpec
	Authority       session.AuthoritySnapshotSpec
	Issuer          kernel.ContributorDescriptor
	Grant           signupStoredGrant
	Checkpoint      []byte
	Admission       signupStoredAdmission
}

const maximumVerificationMFAOutput = 64 << 10

func (s *VerificationSigninService) verificationMFAAAD(b identity.CommandBinding, generation uint64) (envelope.Context, error) {
	if s == nil || s.signup == nil || s.mfa == nil || generation == 0 || b.ValidateFor(verificationSigninOperation()) != nil {
		return envelope.Context{}, email.ErrInvalidVerification
	}
	frame, err := json.Marshal(struct {
		Binding          identity.CommandBinding
		Generation       uint64
		Signup           [32]byte
		Issuer, Audience string
		Lifetime         time.Duration
		Attempts         uint32
	}{b, generation, s.signup.profile, s.mfa.config.IssuerURL, s.c.Profile.Audience, s.mfa.config.Lifetime, s.mfa.config.MaxAttempts})
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, err
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-email-verification-mfa-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *verificationMFAChallengePhase) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	if p == nil || p.service == nil || c != p.original || generation == 0 || p.proof != (capability.Proof{}) {
		return nil, email.ErrInvalidVerification
	}
	if err := p.checkTime(ctx, p.service.c.Issuance.Clock.Now()); err != nil {
		return nil, err
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return nil, err
	}
	i := p.input
	b := i.binding
	f, err := i.flow.Bindings()
	if err != nil {
		return nil, err
	}
	at := i.at.UTC().Truncate(time.Second)
	until := at.Add(p.service.mfa.config.Lifetime)
	primary := i.primary.Payload()
	if primary.ExpiresAt.Before(until) {
		until = primary.ExpiresAt
	}
	if f.Binding.ExpiresAt.Before(until) {
		until = f.Binding.ExpiresAt.UTC().Truncate(time.Second)
	}
	continuation, err := mfa.NewPartialAuthContinuation(mfa.ContinuationSpec{ID: mfa.ContinuationID(id), PrimaryProofID: auth.ProofID(primary.ID), PrimaryProofDigest: i.primary.EnvelopeDigest(), PrimaryProofExpiresAt: primary.ExpiresAt, TenantID: b.TenantID, SubjectID: identity.SubjectID(b.UserID), SourcePreAuthID: f.Binding.ID, Origin: i.request.Origin, AllowedMethods: []string{"totp"}, PolicyVersion: b.PolicyVersion, FactorVersion: i.factor, RememberPolicy: f.Binding.Intent.Remember, Purpose: "identity.mfa.complete", Audience: p.service.c.Profile.Audience, IssuedAt: at, ExpiresAt: until, MaxAttempts: p.service.mfa.config.MaxAttempts, AttemptsRemaining: p.service.mfa.config.MaxAttempts, State: mfa.Pending, Version: 1, VerificationCommandID: identity.CommandID(b.RecordID)})
	if err != nil {
		return nil, err
	}
	payload, err := continuation.CapabilityPayload(p.service.mfa.config.IssuerURL)
	if err != nil {
		return nil, err
	}
	payload.CorrelationID = b.RecordID
	prepared, err := p.service.mfa.issuer.PrepareVerificationMFAContinuation(ctx, b, payload)
	if err != nil {
		return nil, err
	}
	checkpoint, err := p.service.mfa.codec.CheckpointPreparation(ctx, prepared, generation, func(_ context.Context, index uint16, raw []byte) error {
		if index != 0 {
			return email.ErrInvalidVerification
		}
		var e error
		p.proof, e = capability.ParseProof(string(raw), capability.DefaultLimits())
		return e
	})
	defer clear(checkpoint)
	if err != nil {
		return nil, err
	}
	plan, err := prepared.Plan()
	if err != nil || len(plan.Grants) != 1 {
		return nil, email.ErrInvalidVerification
	}
	flow, err := signupFlowProjection(i.flow)
	if err != nil {
		return nil, err
	}
	metadata, err := session.NewMagicLinkAuthentication(session.MagicLinkAuthenticationSpec{CommandID: b.CommandID, RequestCommandID: i.origin.Binding.CommandID, CapabilityID: primary.ID, IdentifierID: i.recipient.Identifier.ID, IdentifierVersion: i.recipient.Identifier.Version, VerificationVersion: i.recipient.Verification.Version, AuthenticatedAt: at, ValidUntil: primary.ExpiresAt})
	if err != nil {
		return nil, err
	}
	m, _ := metadata.Bindings()
	scope, _ := continuation.Bindings()
	scope.RememberPolicy = session.RememberPolicy{}
	authority, _ := i.authority.Bindings()
	out := verificationMFAOutput{Schema: 1, Intent: p.intent, Scope: verificationStoredScope(scope), Flow: flow, Primary: verificationStoredPayload(primary), PrimaryEnvelope: i.primary.EnvelopeDigest(), Metadata: m, Authority: authority, Issuer: plan.Contributor, Grant: signupStoredGrant(plan.Grants[0]), Checkpoint: checkpoint, Admission: signupStoredAdmission(i.admission.Prepared())}
	plain, err := json.Marshal(out)
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > maximumVerificationMFAOutput-4096 {
		return nil, email.ErrInvalidVerification
	}
	aad, err := p.service.verificationMFAAAD(b, generation)
	if err != nil {
		return nil, err
	}
	sealed, err := p.service.signup.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.service.signup.config().ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, err
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > maximumVerificationMFAOutput {
		return nil, email.ErrInvalidVerification
	}
	return wire, nil
}

func (s *VerificationSigninService) readVerificationMFAOutput(ctx context.Context, b identity.CommandBinding, generation uint64, wire []byte) (out verificationMFAOutput, err error) {
	defer func() {
		if err != nil {
			clear(out.Checkpoint)
			out = verificationMFAOutput{}
		}
	}()
	if ctx == nil || len(wire) == 0 || len(wire) > maximumVerificationMFAOutput {
		return out, email.ErrInvalidVerification
	}
	aad, err := s.verificationMFAAAD(b, generation)
	if err != nil {
		return out, err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return out, email.ErrInvalidVerification
	}
	plain, err := s.signup.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > maximumVerificationMFAOutput-4096 {
		return out, email.ErrInvalidVerification
	}
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.Schema != 1 || out.Intent == ([32]byte{}) || out.PrimaryEnvelope == ([32]byte{}) {
		return out, email.ErrInvalidVerification
	}
	canonical, err := json.Marshal(out)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plain) {
		return out, email.ErrInvalidVerification
	}
	return out, nil
}

func (p *verificationMFAChallengePhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	deny := func() (identity.Command, kernel.CommandPlan, error) {
		return identity.Command{}, kernel.CommandPlan{}, email.ErrInvalidVerification
	}
	if p == nil || p.service == nil || c != p.original || c == (identity.Command{}) {
		return deny()
	}
	f, _ := c.Feature()
	stored, err := p.service.readVerificationMFAOutput(ctx, f.Binding, generation, wire)
	if err != nil {
		return deny()
	}
	defer clear(stored.Checkpoint)
	flow, err := signupFlowProjection(p.input.flow)
	authority, _ := p.input.authority.Bindings()
	if err != nil || stored.Intent != p.intent || stored.Flow != flow || !reflect.DeepEqual(stored.Primary, verificationStoredPayload(p.input.primary.Payload())) || stored.PrimaryEnvelope != p.input.primary.EnvelopeDigest() || stored.Authority != authority || stored.Admission.Signature != p.input.admission.Prepared().Signature {
		return deny()
	}
	// The risk owner authenticates its canonical signed representation. Raw Go
	// equality is not a wire contract (for example, time carries clock metadata).
	admission, err := p.service.signup.custody.Restore(ctx, risk.PreparedAuthenticationAdmission(stored.Admission), risk.Context{Tenant: string(f.Binding.TenantID), Operation: risk.Action(f.Binding.OperationID), Attempt: string(f.Binding.CommandID)}, p.input.subject)
	if err != nil {
		return deny()
	}
	p.input.admission = admission
	scope := mfa.ContinuationSpec(stored.Scope)
	if string(scope.VerificationCommandID) != f.Binding.RecordID {
		return deny()
	}
	scope.RememberPolicy, err = session.NewRememberPolicy(stored.Flow.Remember)
	if err != nil {
		return deny()
	}
	continuation, err := mfa.NewPartialAuthContinuation(scope)
	if err != nil {
		return deny()
	}
	if scope.State != mfa.Pending || scope.Version != 1 || scope.MaxAttempts != p.service.mfa.config.MaxAttempts || scope.AttemptsRemaining != scope.MaxAttempts || scope.TenantID != f.Binding.TenantID || scope.SubjectID != identity.SubjectID(f.Binding.UserID) || scope.SourcePreAuthID != flow.ID || scope.Origin != flow.Origin || scope.PrimaryProofID != auth.ProofID(p.input.primary.Payload().ID) || scope.PrimaryProofDigest != stored.PrimaryEnvelope || !scope.PrimaryProofExpiresAt.Equal(p.input.primary.Payload().ExpiresAt) || scope.PolicyVersion != f.Binding.PolicyVersion || scope.FactorVersion != p.input.factor || !reflect.DeepEqual(scope.AllowedMethods, []string{"totp"}) || scope.ExpiresAt.Sub(scope.IssuedAt) > p.service.mfa.config.Lifetime || scope.Audience != p.service.c.Profile.Audience || !scope.IssuedAt.Equal(p.input.at.Truncate(time.Second)) || stored.Metadata.CommandID != f.Binding.CommandID || stored.Metadata.RequestCommandID != p.input.origin.Binding.CommandID || stored.Metadata.CapabilityID != string(scope.PrimaryProofID) || stored.Metadata.IdentifierID != p.input.recipient.Identifier.ID || stored.Metadata.IdentifierVersion != p.input.recipient.Identifier.Version || stored.Metadata.VerificationVersion != p.input.recipient.Verification.Version || !stored.Metadata.AuthenticatedAt.Equal(scope.IssuedAt) || !stored.Metadata.ValidUntil.Equal(scope.PrimaryProofExpiresAt) {
		return deny()
	}
	plan := kernel.CapabilityIssuancePlan{Contributor: stored.Issuer, MFAContinuationUserID: f.Binding.UserID, Grants: []kernel.CapabilityPlan{kernel.CapabilityPlan(stored.Grant)}}
	prepared, err := p.service.mfa.codec.RestorePreparation(ctx, f.Binding, generation, plan, stored.Checkpoint)
	if err != nil {
		return deny()
	}
	f.Fields = append(f.Fields, identity.FeatureField{Name: "mfa.challenge-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(scope.ID)}})
	command, err := identity.NewFeaturePreAuthCommand(f, p.input.request.Browser)
	if err != nil {
		return deny()
	}
	p.command, p.continuation, p.prepared = command, continuation, prepared
	p.outputGeneration, p.outputDigest = generation, sha256.Sum256(wire)
	final, err := p.plan(true)
	if err != nil {
		return deny()
	}
	final, err = p.coordinator.PrepareCommandPlan(f.Binding, command, final)
	if err != nil {
		return deny()
	}
	return command, final, nil
}
