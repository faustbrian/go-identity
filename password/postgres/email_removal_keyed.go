package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// These aliases serialize only inside the existing authenticated encrypted
// request mapping. Raw bearer, CSRF token and initiating key are never retained.
type storedEmailRemovalIntent kernel.EmailRemovalIntent
type storedRemovalKeyBinding kernel.RequestKeyPreparationBinding
type keyedEmailRemovalInput struct {
	Schema        uint8
	Spec          identity.FeatureCommandSpec
	Intent        storedEmailRemovalIntent
	Counter       storedEmailCounter
	FactorVersion uint64
	Proof         []byte
	RequestInput  []identity.FeatureField
}

func (s *EmailRemovalService) requestIntent(r email.AddressRemoveRequest) (identity.RequestIntent, error) {
	if err := r.Validate(); err != nil {
		return identity.RequestIntent{}, err
	}
	proof, err := json.Marshal(r.Primary.Proof)
	if err != nil || len(proof) > maximumReauthenticationRecordBytes {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	defer clear(proof)
	digest := func(purpose string, value []byte) []byte {
		key := s.config().Keyed.intentKey()
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write([]byte("identity-email-removal-input-v1\x00" + purpose + "\x00"))
		_, _ = mac.Write(value)
		return mac.Sum(nil)
	}
	fields := []identity.FeatureField{
		{Name: "profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(s.profile[:])}},
		{Name: "address", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(r.AddressID)}},
		{Name: "identifier-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: r.ExpectedIdentifierVersion}},
		{Name: "verification-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: r.ExpectedVerificationVersion}},
		{Name: "reason", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(r.Reason)}},
		{Name: "primary", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(r.PrimaryDisposition)}},
		{Name: "recovery", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(r.RecoveryDisposition)}},
		{Name: "proof", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("proof", proof)}},
		{Name: "bearer", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("bearer", []byte(r.Primary.Session.Token()))}},
		{Name: "network", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("network", []byte(r.Network))}},
	}
	switch s.primary.config.Transport {
	case session.CredentialCookie:
		state, err := r.Primary.CSRFToken.Digest(s.csrf, session.CSRFBinding{TenantID: r.TenantID, SessionID: "email-removal-intent", SessionVersion: 1})
		if err != nil {
			return identity.RequestIntent{}, identity.ForbiddenError{}
		}
		b, err := state.Bindings()
		if err != nil {
			return identity.RequestIntent{}, identity.ForbiddenError{}
		}
		fields = append(fields, identity.FeatureField{Name: "csrf", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(b.Digest[:])}})
	case session.CredentialBearer:
		if r.Primary.CSRFToken != (session.CSRFToken{}) {
			return identity.RequestIntent{}, identity.ForbiddenError{}
		}
	default:
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	return identity.NewRequestIntent(fields)
}

func (s *EmailRemovalService) requestScope(r email.AddressRemoveRequest, owner kernel.ContributorDescriptor) (kernel.RequestKeyScope, authorization.DecisionContext, kernel.FeatureRegistration) {
	op := emailPrimaryOperation("identity.email.address-remove")
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(s.config().Keyed.RequestKeys.Policy.PolicyVersion)
	caller.Request.Action, caller.Request.Tenant = authorization.Action(op.OperationID), authorization.TenantID(r.TenantID)
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(op.OperationID)}
	return scope, caller, kernel.FeatureRegistration{Contributor: owner, Operation: op}
}

func (p *emailRemovalPhase) requestAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if p == nil || p.service == nil || k.Namespace != p.service.config().Keyed.RequestKeys.Namespace || k.Scope.Method != "POST" || k.Scope.RouteID != "identity.email.address-remove" || k.Feature.Contributor != p.Descriptor() || k.Feature.Operation != emailPrimaryOperation("identity.email.address-remove") || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 || k.PolicyVersion != p.service.config().Keyed.RequestKeys.Policy.PolicyVersion {
		return envelope.Context{}, password.ErrPasswordWork
	}
	frame, err := json.Marshal(struct {
		Binding storedRemovalKeyBinding
		Profile [32]byte
	}{storedRemovalKeyBinding(k), p.service.profile})
	if err != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-email-removal-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *emailRemovalPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	aad, err := p.requestAAD(k)
	if err != nil {
		return nil, err
	}
	prepared, err := p.service.prepareRemoval(ctx, p.request, k.Admission.CommandID)
	if err != nil {
		return nil, err
	}
	spec, ok := prepared.command.Feature()
	fields, has := intent.Fields()
	if !ok || !has || spec.Binding.ActorID != k.Scope.ActorID || spec.Binding.TenantID != k.Scope.TenantID || spec.Binding.ActorKind != k.Scope.ActorKind || spec.Binding.UserID != identity.UserID(k.Scope.ActorID) {
		return nil, identity.ForbiddenError{}
	}
	proof, err := encodeReauthenticationRecord(prepared.primary.custody().record)
	if err != nil {
		return nil, err
	}
	defer clear(proof)
	input := keyedEmailRemovalInput{Schema: 1, Spec: spec, Intent: storedEmailRemovalIntent(prepared.intent), Counter: storedEmailCounter(prepared.counter), FactorVersion: prepared.factorVersion, Proof: proof, RequestInput: fields}
	plain, err := json.Marshal(input)
	defer clear(plain)
	if err != nil || len(plain) > maximumKeyedPasswordCustody-4096 {
		return nil, password.ErrPasswordWork
	}
	sealed, err := p.service.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.service.config().ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, readerFailure(ctx)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > maximumKeyedPasswordCustody {
		clear(wire)
		return nil, password.ErrPasswordWork
	}
	return wire, nil
}

func (p *emailRemovalPhase) restoreRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) error {
	aad, err := p.requestAAD(k)
	if err != nil || len(wire) == 0 || len(wire) > maximumKeyedPasswordCustody {
		return password.ErrPasswordWork
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return password.ErrPasswordWork
	}
	plain, err := p.service.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil {
		return readerFailure(ctx)
	}
	var input keyedEmailRemovalInput
	if decodeKeyedPasswordJSON(plain, &input) != nil || input.Schema != 1 || input.FactorVersion == 0 || len(input.Proof) == 0 || len(input.Proof) > maximumReauthenticationRecordBytes {
		return password.ErrPasswordWork
	}
	defer clear(input.Proof)
	b := input.Spec.Binding
	if b.CommandID != k.Admission.CommandID || b.TenantID != k.Scope.TenantID || b.ActorID != k.Scope.ActorID || b.ActorKind != k.Scope.ActorKind || b.UserID != identity.UserID(k.Scope.ActorID) || b.ValidateFor(k.Feature.Operation) != nil || input.Spec.Operation != k.Feature.Operation {
		return password.ErrPasswordWork
	}
	current, err := p.service.requestIntent(p.request)
	if err != nil {
		return err
	}
	actual, _ := current.Fields()
	expected, err := identity.NewRequestIntent(input.RequestInput)
	if err != nil {
		return password.ErrPasswordWork
	}
	stored, _ := expected.Fields()
	a, err := json.Marshal(actual)
	defer clear(a)
	bw, second := json.Marshal(stored)
	defer clear(bw)
	if err != nil || second != nil || !bytes.Equal(a, bw) {
		return password.ErrPasswordWork
	}
	r := p.request
	primary, err := restoreEmailPrimary(p.service.primary, EmailPrimaryRequest{TenantID: r.TenantID, CommandID: b.CommandID, AddressID: r.AddressID, Session: r.Primary.Session, Proof: r.Primary.Proof, CSRFToken: r.Primary.CSRFToken, Caller: r.Caller.Clone()}, input.Spec.Fields, input.Proof)
	if err != nil {
		return err
	}
	intent := kernel.EmailRemovalIntent(input.Intent)
	if intent.Change.TenantID != b.TenantID || intent.Change.UserID != b.UserID || string(intent.Change.ID) != b.RecordID || intent.Change.ExpectedIdentifierVersion != r.ExpectedIdentifierVersion || intent.Change.ExpectedVerificationVersion != r.ExpectedVerificationVersion || intent.ComparisonProfile != p.service.config().Domain.Directory.ComparisonProfile || intent.Reason != string(r.Reason) || intent.LeavePrimaryUnassigned != (r.PrimaryDisposition == email.LeavePrimaryUnassigned) {
		return password.ErrPasswordWork
	}
	if _, err := kernel.EmailRemovalFields(intent); err != nil {
		return err
	}
	command, err := identity.NewFeatureSessionCommand(input.Spec, r.Primary.Session)
	if err != nil {
		return err
	}
	counter := kernel.CommandCounterPlan(input.Counter)
	if p.service.config().Counters.ValidateCommandCounters(command, counter) != nil {
		return password.ErrPasswordWork
	}
	p.primary, p.intent, p.command, p.counter, p.factorVersion = primary, intent, command, counter, input.FactorVersion
	return nil
}
