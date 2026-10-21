package anonymouspostgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"reflect"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

const maximumSigninFrame = 1 << 20

// Explicit private projections exist only inside the kernel's authenticated
// encrypted input/output. No raw cookie, session token or retry key is stored.
type signinStoredKey kernel.RequestKeyPreparationBinding
type signinStoredCreation identity.CreateUserCommand
type signinStoredSubject anonymous.SubjectSpec
type signinStoredAdmission risk.PreparedAuthenticationAdmission

// Original resolved Remember must be flattened deliberately: the session owner
// does not permit generic serialization of opaque policy/flow custody.
type signinStoredFlow struct {
	BindingID                        identity.PreAuthTransactionID
	Tenant                           identity.TenantID
	Action, Origin, Callback, Policy string
	Nonce                            [32]byte
	Remember                         session.RememberPolicySpec
	PolicyVersion                    uint64
	IssuedAt, ExpiresAt              time.Time
	Cookie                           session.TokenDigest
	Version                          uint64
}

type signinInput struct {
	Schema      uint8
	Binding     identity.CommandBinding
	Creation    signinStoredCreation
	Placeholder identity.Identifier
	Subject     signinStoredSubject
	Flow        signinStoredFlow
	Intent      []identity.FeatureField
}

func storeSigninFlow(flow session.PreAuthTransaction) (signinStoredFlow, error) {
	s, err := flow.Bindings()
	if err != nil {
		return signinStoredFlow{}, err
	}
	i := s.Binding.Intent
	remember, err := i.Remember.Bindings()
	if err != nil || i.Purpose != session.PreAuthSessionIssuance || i.IdentifierBinding != ([32]byte{}) {
		return signinStoredFlow{}, anonymous.ErrInvalidInput
	}
	return signinStoredFlow{s.Binding.ID, i.TenantID, i.Action, i.Origin, i.CallbackURL, i.PolicyID, i.Nonce, remember, i.PolicyVersion, s.Binding.IssuedAt, s.Binding.ExpiresAt, s.Cookie, s.Version}, nil
}
func (f signinStoredFlow) record() (session.PreAuthTransaction, error) {
	r, err := session.NewRememberPolicy(f.Remember)
	if err != nil {
		return session.PreAuthTransaction{}, err
	}
	return session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: f.BindingID, Intent: session.PreAuthIntent{TenantID: f.Tenant, Action: f.Action, Origin: f.Origin, CallbackURL: f.Callback, Nonce: f.Nonce, Remember: r, PolicyID: f.Policy, PolicyVersion: f.PolicyVersion}, IssuedAt: f.IssuedAt, ExpiresAt: f.ExpiresAt}, Cookie: f.Cookie, Version: f.Version})
}

func (s *SigninService) inputAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if k.Feature != (kernel.FeatureRegistration{Contributor: creationOwner(), Operation: creationOperation()}) || k.Scope.Method != "POST" || k.Scope.RouteID != creationOperation().OperationID || k.Namespace != s.config().RequestKeys.Namespace || k.PolicyVersion != s.config().RequestKeys.Policy.PolicyVersion || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, anonymous.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(k.Admission.CommandID)); err != nil {
		return envelope.Context{}, err
	}
	frame, err := json.Marshal(struct {
		Binding signinStoredKey
		Profile [32]byte
	}{signinStoredKey(k), s.profile})
	if err != nil {
		return envelope.Context{}, err
	}
	defer clear(frame)
	sum := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-anonymous-signin-input-v1", "binding": base64.RawURLEncoding.EncodeToString(sum[:])})
}

func (s *SigninService) seal(ctx context.Context, aad envelope.Context, value any) ([]byte, error) {
	return sealAnonymousInput(ctx, s.crypto, s.config().ActiveEnvelopeKeyID, aad, value)
}

func sealAnonymousInput(ctx context.Context, crypto *envelope.Service, keyID string, aad envelope.Context, value any) ([]byte, error) {
	plain, err := json.Marshal(value)
	defer clear(plain)
	if err != nil || len(plain) > maximumSigninFrame-4096 {
		return nil, anonymous.ErrInvalidInput
	}
	sealed, err := crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: keyID, Context: aad})
	if err != nil {
		return nil, signinPublicError(ctx, err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > maximumSigninFrame {
		return nil, anonymous.ErrInvalidInput
	}
	return wire, nil
}

func (s *SigninService) open(ctx context.Context, aad envelope.Context, wire []byte, into any) error {
	return openAnonymousInput(ctx, s.crypto, aad, wire, into)
}

func openAnonymousInput(ctx context.Context, crypto *envelope.Service, aad envelope.Context, wire []byte, into any) error {
	if ctx == nil || len(wire) == 0 || len(wire) > maximumSigninFrame {
		return anonymous.ErrInvalidInput
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return anonymous.ErrInvalidInput
	}
	plain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > maximumSigninFrame-4096 {
		return signinPublicError(ctx, identity.UnavailableError{})
	}
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(into) != nil || d.Decode(new(any)) != io.EOF {
		return anonymous.ErrInvalidInput
	}
	return ctx.Err()
}

func (p *signinPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	s, c, r := p.service, p.service.config(), p.request
	if r.Validate() != nil || !slices.Contains(c.Origins, r.Origin) || !slices.Contains(c.CallbackURLs, r.CallbackURL) || r.TenantID != k.Scope.TenantID || identity.ActorID(r.Caller.Request.Subject.ID) != k.Scope.ActorID || r.Caller.Request.Subject.Kind != k.Scope.ActorKind {
		return nil, anonymous.ErrInvalidInput
	}
	aad, err := s.inputAAD(k)
	if err != nil {
		return nil, err
	}
	flow, err := sessionpg.ReadPreAuth(ctx, s.pool.Raw(), c.Sessions, r.TenantID, r.PreAuthID)
	if err != nil {
		return nil, signinPublicError(ctx, err)
	}
	var at time.Time
	if err = s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return nil, identity.UnavailableError{}
	}
	if _, err = p.admitFlow(flow, at, false); err != nil {
		return nil, err
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	b := identity.CommandBinding{CommandID: k.Admission.CommandID, TenantID: k.Scope.TenantID, ActorID: k.Scope.ActorID, ActorKind: k.Scope.ActorKind, AnonymousFlowID: string(r.PreAuthID), OperationID: creationOperation().OperationID, SchemaID: creationOperation().SchemaID, SchemaVersion: 1, PolicyID: c.PolicyID, PolicyVersion: k.PolicyVersion, CorrelationID: string(k.Admission.CommandID)}
	creation := b
	creation.UserID, creation.AnonymousFlowID, creation.OperationID = identity.UserID(id), "", "identity.user.create"
	creation.SchemaID, creation.SchemaVersion = c.FieldSchema.ID, c.FieldSchema.Version
	policy, _ := c.Policy.Config()
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(b.PolicyVersion)
	caller.Request.Action = "identity.user.create"
	caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(id)}
	attributes, err := c.Fields.Prepare(ctx, identity.AttributePrepareRequest{TenantID: b.TenantID, UserID: identity.UserID(id), SchemaVersion: c.FieldSchema.Version, Context: caller, Updates: []identity.AttributeUpdate{{Name: c.DisplayNameField, Value: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: policy.DisplayName}}}}})
	if err != nil {
		return nil, err
	}
	storedFlow, err := storeSigninFlow(flow)
	if err != nil {
		return nil, err
	}
	fields, ok := intent.Fields()
	if !ok {
		return nil, anonymous.ErrInvalidInput
	}
	input := signinInput{Schema: 1, Binding: b, Creation: signinStoredCreation(identity.CreateUserCommand{Binding: creation, Status: identity.StatusActive, Attributes: attributes}), Placeholder: identity.Identifier{ID: identity.IdentifierID(id), UserID: identity.UserID(id), Kind: identity.IdentifierAnonymousPlaceholder, CanonicalValue: string(id) + "@anonymous.invalid", Version: 1}, Subject: signinStoredSubject(anonymous.SubjectSpec{ID: id, TenantID: b.TenantID, UserID: identity.UserID(id), CreatedAt: at.UTC().Truncate(time.Microsecond), ExpiresAt: at.UTC().Truncate(time.Microsecond).Add(policy.TTL), State: anonymous.StateActive, Version: 1, Cleanup: policy.Cleanup}), Flow: storedFlow, Intent: fields}
	if err = p.validateInput(k, input, intent); err != nil {
		return nil, err
	}
	return s.seal(ctx, aad, input)
}

func (p *signinPhase) validateInput(k kernel.RequestKeyPreparationBinding, input signinInput, current identity.RequestIntent) error {
	c := p.service.config()
	b := input.Binding
	subject := anonymous.SubjectSpec(input.Subject)
	creation := identity.CreateUserCommand(input.Creation)
	policy, _ := c.Policy.Config()
	if input.Schema != 1 || b.ValidateFor(creationOperation()) != nil || b.CommandID != k.Admission.CommandID || b.TenantID != k.Scope.TenantID || b.ActorID != k.Scope.ActorID || b.ActorKind != k.Scope.ActorKind || b.PolicyID != c.PolicyID || b.PolicyVersion != k.PolicyVersion || b.AnonymousFlowID != string(input.Flow.BindingID) || b.CorrelationID != string(b.CommandID) || subject.TenantID != b.TenantID || subject.State != anonymous.StateActive || subject.Version != 1 || subject.Cleanup != policy.Cleanup || subject.ExpiresAt.Sub(subject.CreatedAt) != policy.TTL || subject.CreatedAt.Before(input.Flow.IssuedAt) || !subject.CreatedAt.Before(input.Flow.ExpiresAt) {
		return anonymous.ErrInvalidInput
	}
	if _, err := anonymous.NewAnonymousSubject(subject); err != nil {
		return err
	}
	expected := b
	expected.UserID, expected.AnonymousFlowID, expected.OperationID = subject.UserID, "", "identity.user.create"
	expected.SchemaID, expected.SchemaVersion = c.FieldSchema.ID, c.FieldSchema.Version
	if creation.Binding != expected || creation.Status != identity.StatusActive {
		return anonymous.ErrInvalidInput
	}
	if _, err := kernel.AnonymousCreationFields(kernel.AnonymousCreationIntent{Creation: creation, Placeholder: input.Placeholder}); err != nil {
		return err
	}
	flow, err := input.Flow.record()
	if err != nil {
		return err
	}
	f, _ := flow.Bindings()
	i := f.Binding.Intent
	if i.TenantID != b.TenantID || i.Action != b.OperationID || i.PolicyID != b.PolicyID || i.PolicyVersion != b.PolicyVersion || !slices.Contains(c.Origins, i.Origin) || !slices.Contains(c.CallbackURLs, i.CallbackURL) {
		return anonymous.ErrInvalidInput
	}
	if len(input.Intent) != 3 {
		return anonymous.ErrInvalidInput
	}
	retained, err := identity.NewRequestIntent(input.Intent)
	if err != nil {
		return err
	}
	values, _ := retained.Fields()
	for _, field := range values {
		if field.Value.Kind != identity.FeatureBytes || len(field.Value.Bytes) != 32 {
			return anonymous.ErrInvalidInput
		}
		switch field.Name {
		case "profile":
			if !hmac.Equal(field.Value.Bytes, p.service.profile[:]) {
				return anonymous.ErrInvalidInput
			}
		case "input", "cookie":
		default:
			return anonymous.ErrInvalidInput
		}
	}
	if actual, ok := current.Fields(); ok && !reflect.DeepEqual(actual, values) {
		return identity.ConflictError{}
	}
	return nil
}

func (p *signinPhase) restoreInput(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte, intent identity.RequestIntent) error {
	aad, err := p.service.inputAAD(k)
	if err != nil {
		return err
	}
	var input signinInput
	if err = p.service.open(ctx, aad, wire, &input); err != nil {
		return err
	}
	if err = p.validateInput(k, input, intent); err != nil {
		return err
	}
	p.input = input
	p.flow, err = input.Flow.record()
	return err
}

func (p *signinPhase) possessesRecovery(r anonymous.SigninRecoveryRequest) bool {
	s, err := p.flow.Bindings()
	if err != nil || r.Origin != s.Binding.Intent.Origin || !slices.Contains(p.service.config().Origins, r.Origin) {
		return false
	}
	token, err := session.ParseToken(r.Cookie.Token())
	if err != nil {
		return false
	}
	for _, key := range p.service.config().FlowKeys {
		digest, e := token.PreAuthDigest(key, s.Binding)
		if e == nil && digest.KeyVersion == s.Cookie.KeyVersion && hmac.Equal(digest.Sum[:], s.Cookie.Sum[:]) {
			return true
		}
	}
	return false
}

func (p *signinPhase) admitFlow(flow session.PreAuthTransaction, at time.Time, recovery bool) (session.DigestKey, error) {
	r, c := p.request, p.service.config()
	f, err := flow.Bindings()
	if err != nil {
		return session.DigestKey{}, identity.ForbiddenError{}
	}
	i := f.Binding.Intent
	if f.Binding.ID != r.PreAuthID || i.TenantID != r.TenantID || i.Action != creationOperation().OperationID || i.Origin != r.Origin || i.CallbackURL != r.CallbackURL || i.PolicyID != c.PolicyID || i.PolicyVersion != c.RequestKeys.Policy.PolicyVersion || i.Remember != r.Remember || i.Purpose != session.PreAuthSessionIssuance || i.IdentifierBinding != ([32]byte{}) {
		return session.DigestKey{}, identity.ForbiddenError{}
	}
	token, err := session.ParseToken(r.Cookie.Token())
	if err != nil {
		return session.DigestKey{}, identity.ForbiddenError{}
	}
	for _, key := range c.FlowKeys {
		d, e := token.PreAuthDigest(key, f.Binding)
		if e == nil && d.KeyVersion == f.Cookie.KeyVersion && hmac.Equal(d.Sum[:], f.Cookie.Sum[:]) && (recovery || flow.Check(at, f.Binding, d) == nil) {
			return key, nil
		}
	}
	return session.DigestKey{}, identity.ForbiddenError{}
}
