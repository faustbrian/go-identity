package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// These surrogate scalars enter only the existing encrypted request mapping.
// Signed proof/original session fields already belong to the primary owner;
// retain those unchanged rather than create another proof or session record.
// Bearer, raw CSRF and caller retry key are never persisted, even encrypted.
type storedPhoneEnrollmentIntent kernel.PhoneEnrollmentIntent
type phoneEnrollmentStoredInput struct {
	Schema          uint8
	Spec            identity.FeatureCommandSpec
	Intent          storedPhoneEnrollmentIntent
	Number          phone.NumberRecord
	Network, Device string
	FactorVersion   uint64
	At, Until       time.Time
	RequestInput    []identity.FeatureField
}

func (s *phoneVerificationService) enrollmentRequestIntent(r phone.EnrollmentRequestSpec) (identity.RequestIntent, error) {
	if r.Validate() != nil {
		return identity.RequestIntent{}, phone.ErrInvalidVerification
	}
	number, err := r.Number.Record()
	if err != nil {
		return identity.RequestIntent{}, err
	}
	numberWire, err := json.Marshal(number)
	if err != nil {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	defer clear(numberWire)
	proof, err := json.Marshal(r.Proof)
	if err != nil || len(proof) > maximumReauthenticationRecordBytes {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	defer clear(proof)
	digest := func(purpose string, value []byte) []byte {
		key := s.config().IntentKey
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write([]byte("identity-phone-enrollment-input-v1\x00" + purpose + "\x00"))
		_, _ = mac.Write(value)
		return mac.Sum(nil)
	}
	fields := []identity.FeatureField{
		{Name: "profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(s.profile[:])}},
		{Name: "number", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("number", numberWire)}},
		{Name: "proof", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("proof", proof)}},
		{Name: "bearer", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("bearer", []byte(r.Session.Token()))}},
		{Name: "network", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("network", []byte(r.Network))}},
		{Name: "device", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("device", []byte(r.Device))}},
	}
	switch s.primary.primary.config.Transport {
	case session.CredentialCookie:
		csrf, err := r.CSRFToken.Digest(s.csrf, session.CSRFBinding{TenantID: r.TenantID, SessionID: "phone-enrollment-intent", SessionVersion: 1})
		if err != nil {
			return identity.RequestIntent{}, identity.ForbiddenError{}
		}
		b, err := csrf.Bindings()
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

func (s *phoneVerificationService) enrollmentRequestScope(r phone.EnrollmentRequestSpec, owner kernel.ContributorDescriptor) (kernel.RequestKeyScope, authorization.DecisionContext, kernel.FeatureRegistration) {
	op := phoneEnrollmentOperation()
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(s.config().RequestKeys.Policy.PolicyVersion)
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(op.OperationID)}
	return scope, caller, kernel.FeatureRegistration{Contributor: owner, Operation: op}
}

func (s *phoneVerificationService) enrollmentInputAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if k.Namespace != s.config().RequestKeys.Namespace || k.Scope.Method != "POST" || k.Scope.RouteID != phoneEnrollmentOperation().OperationID || k.Feature.Contributor != phoneVerificationDescriptor() || k.Feature.Operation != phoneEnrollmentOperation() || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 || k.PolicyVersion != s.config().RequestKeys.Policy.PolicyVersion {
		return envelope.Context{}, password.ErrPasswordWork
	}
	frame, err := json.Marshal(struct {
		Binding storedRemovalKeyBinding
		Profile [32]byte
	}{storedRemovalKeyBinding(k), s.profile})
	if err != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-phone-enrollment-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *phoneEnrollmentPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	aad, err := p.service.enrollmentInputAAD(k)
	if err != nil {
		return nil, err
	}
	prepared, err := p.service.prepareEnrollment(ctx, p.request, k.Admission.CommandID)
	if err != nil {
		return nil, err
	}
	spec, ok := prepared.command.Feature()
	fields, has := intent.Fields()
	if !ok || !has || spec.Binding.ActorID != k.Scope.ActorID || spec.Binding.TenantID != k.Scope.TenantID || spec.Binding.ActorKind != k.Scope.ActorKind {
		return nil, identity.ForbiddenError{}
	}
	number, err := p.request.Number.Record()
	if err != nil {
		return nil, err
	}
	input := phoneEnrollmentStoredInput{Schema: 1, Spec: spec, Intent: storedPhoneEnrollmentIntent(prepared.intent), Number: number, Network: p.request.Network, Device: p.request.Device, FactorVersion: prepared.factorVersion, At: prepared.at, Until: prepared.until, RequestInput: fields}
	plain, err := json.Marshal(input)
	defer clear(plain)
	if err != nil || len(plain) > maximumKeyedPasswordCustody-4096 {
		return nil, password.ErrPasswordWork
	}
	return p.service.sealPhone(ctx, plain, aad)
}

func (s *phoneVerificationService) sealPhone(ctx context.Context, plain []byte, aad envelope.Context) ([]byte, error) {
	sealed, err := s.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: s.config().ActiveEnvelopeKeyID, Context: aad})
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
func (s *phoneVerificationService) openPhone(ctx context.Context, wire []byte, aad envelope.Context) ([]byte, error) {
	if len(wire) == 0 || len(wire) > maximumKeyedPasswordCustody {
		return nil, password.ErrPasswordWork
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	plain, err := s.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil {
		clear(plain)
		return nil, readerFailure(ctx)
	}
	if len(plain) == 0 || len(plain) > maximumKeyedPasswordCustody {
		clear(plain)
		return nil, password.ErrPasswordWork
	}
	return plain, nil
}

func (s *phoneVerificationService) readEnrollmentInput(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte, bearer auth.BearerCredential, caller authorization.DecisionContext, csrf session.CSRFToken) (*phoneEnrollmentPhase, phoneEnrollmentStoredInput, error) {
	bad := func(err error) (*phoneEnrollmentPhase, phoneEnrollmentStoredInput, error) {
		return nil, phoneEnrollmentStoredInput{}, err
	}
	aad, err := s.enrollmentInputAAD(k)
	if err != nil {
		return bad(err)
	}
	plain, err := s.openPhone(ctx, wire, aad)
	if err != nil {
		return bad(err)
	}
	defer clear(plain)
	var input phoneEnrollmentStoredInput
	if decodeKeyedPasswordJSON(plain, &input) != nil || input.Schema != 1 || input.FactorVersion == 0 || input.At.IsZero() || input.Until.IsZero() || !input.Until.After(input.At) || input.At != input.At.UTC().Truncate(time.Microsecond) || input.Until != input.Until.UTC().Truncate(time.Microsecond) {
		return bad(password.ErrPasswordWork)
	}
	b := input.Spec.Binding
	candidate, err := phoneEnrollmentIdentifier(b.CommandID)
	if err != nil || b.CommandID != k.Admission.CommandID || b.TenantID != k.Scope.TenantID || b.ActorID != k.Scope.ActorID || b.ActorKind != k.Scope.ActorKind || b.UserID != identity.UserID(caller.Request.Subject.ID) || b.ValidateFor(k.Feature.Operation) != nil || input.Spec.Operation != k.Feature.Operation || b.RecordID != string(candidate) || b.PolicyID != s.config().PolicyID || b.PolicyVersion != s.config().RequestKeys.Policy.PolicyVersion {
		return bad(password.ErrPasswordWork)
	}
	if _, err = identity.NewRequestIntent(input.RequestInput); err != nil {
		return bad(password.ErrPasswordWork)
	}
	command, err := identity.NewFeatureSessionCommand(input.Spec, bearer)
	if err != nil {
		return bad(err)
	}
	if !phoneCommandProfile(command, s.profile, input.FactorVersion) {
		return bad(password.ErrPasswordWork)
	}
	primary, err := s.primary.RestoreCommand(ctx, command, caller, csrf)
	if err != nil {
		return bad(err)
	}
	intent := kernel.PhoneEnrollmentIntent(input.Intent)
	if intent.Change.TenantID != b.TenantID || intent.Change.UserID != b.UserID || string(intent.Change.ID) != b.RecordID || intent.Change.CanonicalValue != input.Number.E164 || intent.Change.DisplayValue != input.Number.Display || intent.Change.NormalizationProfile != input.Number.Profile.ID || intent.Change.NormalizationVersion != input.Number.Profile.Version {
		return bad(password.ErrPasswordWork)
	}
	if _, err = s.policy.Restore(ctx, input.Number); err != nil {
		return bad(err)
	}
	if _, err = kernel.PhoneEnrollmentFields(intent); err != nil {
		return bad(err)
	}
	subject := s.authenticationSubject(b.TenantID, input.Number.E164, input.Network, input.Device)
	if !reauthenticationText(input.Network, 128) || !reauthenticationText(input.Device, 128) {
		return bad(password.ErrPasswordWork)
	}
	original, err := primary.Original()
	if err != nil {
		return bad(err)
	}
	deadline, err := primary.Deadline()
	if err != nil || input.Until != deadline.UTC().Truncate(time.Microsecond) {
		return bad(password.ErrPasswordWork)
	}
	inputCustody, err := s.config().Issuer.CaptureInput(ctx, b, intent, original, input.At, input.Until)
	if err != nil {
		return bad(err)
	}
	return &phoneEnrollmentPhase{service: s, primary: primary, intent: intent, command: command, subject: subject, factorVersion: input.FactorVersion, input: inputCustody, at: input.At, until: input.Until}, input, nil
}

func (p *phoneEnrollmentPhase) restoreRequest(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) error {
	restored, input, err := p.service.readEnrollmentInput(ctx, k, wire, p.request.Session, p.request.Caller, p.request.CSRFToken)
	if err != nil {
		return err
	}
	current, err := p.service.enrollmentRequestIntent(p.request)
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
	b, e := json.Marshal(stored)
	defer clear(b)
	if err != nil || e != nil || !bytes.Equal(a, b) {
		return identity.ForbiddenError{}
	}
	p.primary, p.intent, p.command, p.subject, p.factorVersion, p.input, p.at, p.until = restored.primary, restored.intent, restored.command, restored.subject, restored.factorVersion, restored.input, restored.at, restored.until
	return nil
}

type phoneAuthenticationAdmission risk.PreparedAuthenticationAdmission
