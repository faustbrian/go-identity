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
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Original signed proof scalars already live in Spec's authenticated fields.
// Do not invent another proof record/map. This structure is exported only into
// the existing authenticated encrypted request-key preparation. Candidate and
// proof fields never persist outside that ciphertext; bearer, CSRF token and
// initiating retry key are not retained even inside it.
type storedPhoneRemovalIntent kernel.PhoneRemovalIntent
type keyedPhoneRemovalInput struct {
	Schema        uint8
	Spec          identity.FeatureCommandSpec
	Intent        storedPhoneRemovalIntent
	Counter       storedEmailCounter
	FactorVersion uint64
	RequestInput  []identity.FeatureField
}

func (s *phoneRemovalService) requestIntent(r phone.RemoveRequestSpec) (identity.RequestIntent, error) {
	if !validEmailPrimaryCaller(r.Caller) || r.Validate() != nil {
		return identity.RequestIntent{}, phone.ErrInvalidRemoval
	}
	record, err := r.Number.Record()
	if err != nil {
		return identity.RequestIntent{}, err
	}
	number, err := json.Marshal(struct {
		Value, Profile string
		Version        uint32
	}{record.E164, record.Profile.ID, record.Profile.Version})
	if err != nil {
		return identity.RequestIntent{}, err
	}
	defer clear(number)
	proof, err := json.Marshal(r.Proof)
	if err != nil || len(proof) > maximumReauthenticationRecordBytes {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	defer clear(proof)
	digest := func(purpose string, value []byte) []byte {
		key := s.config().IntentKey
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write([]byte("identity-phone-removal-input-v1\x00" + purpose + "\x00"))
		_, _ = mac.Write(value)
		return mac.Sum(nil)
	}
	fields := []identity.FeatureField{
		{Name: "profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(s.profile[:])}},
		{Name: "identifier", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(r.IdentifierID)}},
		{Name: "identifier-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: r.ExpectedIdentifierVersion}},
		{Name: "verification-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: r.ExpectedVerificationVersion}},
		{Name: "number", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("number", number)}},
		{Name: "reason", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(r.Reason)}},
		{Name: "proof", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("proof", proof)}},
		{Name: "bearer", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("bearer", []byte(r.Session.Token()))}},
		{Name: "network", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("network", []byte(r.Network))}},
	}
	switch s.primary.primary.config.Transport {
	case session.CredentialCookie:
		state, err := r.CSRFToken.Digest(s.csrf, session.CSRFBinding{TenantID: r.TenantID, SessionID: "phone-removal-intent", SessionVersion: 1})
		if err != nil {
			return identity.RequestIntent{}, identity.ForbiddenError{}
		}
		b, err := state.Bindings()
		if err != nil {
			return identity.RequestIntent{}, identity.ForbiddenError{}
		}
		fields = append(fields, identity.FeatureField{Name: "csrf", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(b.Digest[:])}})
	case session.CredentialBearer:
		if r.CSRFToken != (session.CSRFToken{}) {
			return identity.RequestIntent{}, identity.ForbiddenError{}
		}
	default:
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	return identity.NewRequestIntent(fields)
}
func (s *phoneRemovalService) requestScope(r phone.RemoveRequestSpec, owner kernel.ContributorDescriptor) (kernel.RequestKeyScope, authorization.DecisionContext, kernel.FeatureRegistration) {
	op := actionPrimaryOperation("identity.phone.remove")
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(s.config().RequestKeys.Policy.PolicyVersion)
	caller.Request.Action, caller.Request.Tenant = authorization.Action(op.OperationID), authorization.TenantID(r.TenantID)
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(op.OperationID)}
	return scope, caller, kernel.FeatureRegistration{Contributor: owner, Operation: op}
}
func (p *phoneRemovalPhase) requestAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if p == nil || p.service == nil || k.Namespace != p.service.config().RequestKeys.Namespace || k.Scope.Method != "POST" || k.Scope.RouteID != "identity.phone.remove" || k.Feature.Contributor != p.Descriptor() || k.Feature.Operation != p.FeatureOperations()[0] || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 || k.PolicyVersion != p.service.config().RequestKeys.Policy.PolicyVersion {
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
	return envelope.NewContext(map[string]string{"profile": "identity-phone-removal-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}
func (p *phoneRemovalPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
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
	if !ok || !has || spec.Binding.ActorID != k.Scope.ActorID || spec.Binding.TenantID != k.Scope.TenantID || spec.Binding.ActorKind != k.Scope.ActorKind || spec.Binding.UserID != identity.UserID(p.request.Caller.Request.Subject.ID) {
		return nil, identity.ForbiddenError{}
	}
	input := keyedPhoneRemovalInput{Schema: 1, Spec: spec, Intent: storedPhoneRemovalIntent(prepared.intent), Counter: storedEmailCounter(prepared.counter), FactorVersion: prepared.factorVersion, RequestInput: fields}
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
func (p *phoneRemovalPhase) restoreRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) error {
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
	var input keyedPhoneRemovalInput
	if decodeKeyedPasswordJSON(plain, &input) != nil || input.Schema != 1 || input.FactorVersion == 0 {
		return password.ErrPasswordWork
	}
	b := input.Spec.Binding
	r := p.request
	if b.CommandID != k.Admission.CommandID || b.TenantID != k.Scope.TenantID || b.ActorID != k.Scope.ActorID || b.ActorKind != k.Scope.ActorKind || b.UserID != identity.UserID(r.Caller.Request.Subject.ID) || b.ValidateFor(k.Feature.Operation) != nil || input.Spec.Operation != k.Feature.Operation {
		return password.ErrPasswordWork
	}
	current, err := p.service.requestIntent(r)
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
	command, err := identity.NewFeatureSessionCommand(input.Spec, r.Session)
	if err != nil {
		return err
	}
	primary, err := p.service.primary.RestoreCommand(ctx, command, r.Caller.Clone(), r.CSRFToken)
	if err != nil {
		return err
	}
	intent := kernel.PhoneRemovalIntent(input.Intent)
	if intent.Change.TenantID != b.TenantID || intent.Change.UserID != b.UserID || string(intent.Change.ID) != b.RecordID || intent.Change.ID != r.IdentifierID || intent.Change.ExpectedIdentifierVersion != r.ExpectedIdentifierVersion || intent.Change.ExpectedVerificationVersion != r.ExpectedVerificationVersion || intent.NormalizationProfile != p.service.config().Domain.Directory.NormalizationProfile || intent.NormalizationVersion != p.service.config().Domain.Directory.NormalizationVersion || intent.Reason != string(r.Reason) {
		return password.ErrPasswordWork
	}
	number, err := r.Number.Record()
	if err != nil || intent.CanonicalNumber != number.E164 || intent.NormalizationProfile != number.Profile.ID || intent.NormalizationVersion != number.Profile.Version {
		return password.ErrPasswordWork
	}
	if _, err := kernel.PhoneRemovalFields(intent); err != nil {
		return err
	}
	counter := kernel.CommandCounterPlan(input.Counter)
	if p.service.counters.ValidateCommandCounters(command, counter) != nil {
		return password.ErrPasswordWork
	}
	p.primary, p.intent, p.command, p.counter, p.factorVersion = primary, intent, command, counter, input.FactorVersion
	return nil
}
