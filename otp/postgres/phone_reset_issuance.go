package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// PhonePasswordResetIssuerConfig selects the existing native OTP/send-family
// and encrypted SMS delivery owners. Store must contain actual recovery pre-auth
// cookie admission. The registered phone owner separately admits request risk,
// current primary/recipient/factor and canonical reset-capability issuance in
// its sole Work. No consuming OTP participant is enlisted for this request.
// Borrowed configuration/owners must remain immutable during concurrent calls.
type PhonePasswordResetIssuerConfig struct {
	Store           ContributorConfig
	Delivery        *deliverypg.Contributor
	Policy          otp.AttemptPolicy
	TemplateID      string
	TemplateVersion uint32
	ProviderVersion uint64
	LocaleChain     []string
	Templates       []delivery.Template
}

// PhonePasswordResetIssuer owns no transaction, journal, goroutine or lifetime.
// It supplies only the original sessionless recovery SMS, not reset permission,
// TOTP verification, a session or another attempt budget. Zero denies.
type PhonePasswordResetIssuer struct {
	read func() *phonePasswordResetIssuer
}
type phonePasswordResetIssuer struct {
	store         *Contributor
	configuration [32]byte
}

func (s *PhonePasswordResetIssuer) state() *phonePasswordResetIssuer {
	if s == nil || s.read == nil {
		return nil
	}
	return s.read()
}

// NewPhonePasswordResetIssuer freezes only password-reset/SMS consuming-code
// policy. Install existing OTP/send-family/issuance/delivery histories and call
// Initialize before use. It performs no IO, entropy, rendering or admission.
func NewPhonePasswordResetIssuer(c PhonePasswordResetIssuerConfig) (*PhonePasswordResetIssuer, error) {
	profile, checks, err := c.Policy.Bindings()
	if err != nil || profile.Purpose != otp.PurposePasswordReset || checks.Enabled || c.Delivery == nil {
		return nil, ErrInvalidConfiguration
	}
	store, err := NewContributor(c.Store)
	if err != nil || store.preauth == nil {
		return nil, ErrInvalidConfiguration
	}
	store, err = newPreparedSendContributor(store, c.Delivery, preparedSendConfig{preparation: otp.SendPreparationConfig{Policy: c.Policy, TemplateID: c.TemplateID, TemplateVersion: c.TemplateVersion, LocaleChain: c.LocaleChain}, provider: c.ProviderVersion, templates: c.Templates, contributors: []kernel.ContributorDescriptor{{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}, c.Delivery.Descriptor()}})
	if err != nil {
		return nil, err
	}
	frame := append(make([]byte, 0, 4096), []byte("identity-otp-phone-reset-request-owner-v1\x00")...)
	frame = append(frame, store.send.configuration[:]...)
	defer func() { clear(frame) }()
	frame = append(frame, store.codec.configuration[:]...)
	lockout := store.lockout.binding()
	frame = append(frame, lockout[:]...)
	for _, value := range []string{store.schema, store.global, store.namespace, store.preauth.config.Schema} {
		frame = appendAuthorityText(frame, value)
	}
	frame = binary.BigEndian.AppendUint64(frame, uint64(store.preauth.config.MaximumDuration))
	versions := make([]uint32, 0, len(c.Store.PreAuthCookieKeys))
	for version := range c.Store.PreAuthCookieKeys {
		versions = append(versions, version)
	}
	slices.Sort(versions)
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(versions)))
	for _, version := range versions {
		frame = binary.BigEndian.AppendUint32(frame, version)
		frame = binary.BigEndian.AppendUint32(frame, uint32(len(c.Store.PreAuthCookieKeys[version])))
		frame = append(frame, c.Store.PreAuthCookieKeys[version]...)
	}
	policy, err := json.Marshal(struct {
		Profile otp.CodeProfileSpec
		Checks  otp.CheckPolicySpec
	}{profile, checks})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	frame = append(frame, policy...)
	clear(policy)
	p := &phonePasswordResetIssuer{store: store, configuration: sha256.Sum256(frame)}
	return &PhonePasswordResetIssuer{read: func() *phonePasswordResetIssuer { return p }}, nil
}

// Initialize binds existing digest keys and lockout policy with bounded startup
// IO. Exact retries are idempotent; uncertainty never creates replacement codes.
// The caller owns pool lifetime. No schema or business record is installed.
func (s *PhonePasswordResetIssuer) Initialize(ctx context.Context, pool *database.Pool) error {
	p := s.state()
	if p == nil {
		return ErrInvalidConfiguration
	}
	return initializeIssuanceKeys(ctx, pool, p.store, p.store.codec.maximumDuration, p.store.codec.codeVersions)
}

// Configuration is immutable preparation identity, never current permission.
func (s *PhonePasswordResetIssuer) Configuration() ([32]byte, error) {
	p := s.state()
	if p == nil {
		return [32]byte{}, ErrInvalidConfiguration
	}
	return p.configuration, nil
}

// DeliveryContributor returns the existing borrowed encrypted-effect owner.
func (s *PhonePasswordResetIssuer) DeliveryContributor() *deliverypg.Contributor {
	p := s.state()
	if p == nil {
		return nil
	}
	return p.store.send.delivery
}

// PhonePasswordResetSendInput retains code/bearer-free original intent behind
// diagnostic-safe closure custody. CaptureInput is its only producer. It is
// structural, not authentication, risk clearance or current factor permission.
// Copies share immutable encrypted factor custody; no resource is owned.
type PhonePasswordResetSendInput struct {
	read func() phonePasswordResetSendInput
}
type phonePasswordResetSendInput struct {
	binding identity.CommandBinding
	record  sendRequestRecord
	factor  mfapg.TOTPFactorSnapshot
}

func (i PhonePasswordResetSendInput) state() phonePasswordResetSendInput {
	if i.read == nil {
		return phonePasswordResetSendInput{}
	}
	return i.read()
}

// CaptureInput freezes actual original recovery pre-auth, independently selected
// verified phone/password authority and confirmed encrypted factor. At is the
// request's original database instant; Until cannot exceed the original flow or
// OTP TTL. Nothing is renewed, decrypted, generated or persisted. Native phone
// preparation must authenticate the actual cookie/current owners before its
// acknowledged generation marker; Persist independently fences them again.
func (s *PhonePasswordResetIssuer) CaptureInput(ctx context.Context, b identity.CommandBinding, original session.PreAuthTransaction, recipient kernel.RecipientRecord, authority AttemptAuthority, factor mfapg.TOTPFactorSnapshot, at, until time.Time) (PhonePasswordResetSendInput, error) {
	bad := func(err error) (PhonePasswordResetSendInput, error) { return PhonePasswordResetSendInput{}, err }
	p := s.state()
	if ctx == nil || p == nil || b.ValidateFor(phoneResetSendOperation()) != nil || !nativeTime(at) || !nativeTime(until) || !until.After(at) {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	f, err := original.Bindings()
	if err != nil || original.Check(at, f.Binding, f.Cookie) != nil {
		return bad(ErrInvalidCommand)
	}
	profile, _, _ := p.store.send.policy.Bindings()
	for _, cap := range []time.Time{at.Add(profile.TTL), f.Binding.ExpiresAt} {
		if cap.Before(until) {
			until = cap.UTC().Truncate(time.Microsecond)
		}
	}
	flow, err := otp.NewBoundPreAuthAuthorization(original)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	destination, err := otp.NewDestinationInput(recipient.Query.CanonicalValue)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	c, err := otp.NewContinuation(otp.DigestScopeSpec{TenantID: string(b.TenantID), SubjectID: string(b.UserID), Purpose: otp.PurposePasswordReset, Channel: otp.ChannelSMS, Destination: destination, ChallengeID: string(b.CommandID), TargetID: string(authority.Credential.ID), PolicyVersion: b.PolicyVersion, Generation: 1}, flow, session.RememberPolicy{})
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	r := sendRequestRecord{continuation: c, policy: p.store.send.policy, authority: authority, recipient: &recipient, issuedAt: at, expiresAt: until}
	if r.validate(b) != nil {
		return bad(ErrInvalidCommand)
	}
	input := phonePasswordResetSendInput{binding: b, record: r, factor: factor}
	i := PhonePasswordResetSendInput{read: func() phonePasswordResetSendInput { return input }}
	if _, err := i.Fields(); err != nil {
		return bad(err)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	return i, nil
}

// Fields returns only the original factor-selection triplet for native request
// fingerprinting. These scalar fields are not current authority or factor proof.
func (i PhonePasswordResetSendInput) Fields() ([]identity.FeatureField, error) {
	s := i.state()
	m, err := s.factor.Metadata()
	if err != nil || s.record.validate(s.binding) != nil || m.TenantID != s.binding.TenantID || m.UserID != s.binding.UserID || m.FactorID == "" || m.EnrollmentVersion == 0 || m.RowVersion == 0 || m.FactorAuthorityVersion == 0 || m.ContinuationID != "" || m.ContinuationVersion != 0 || m.ScopeDigest != ([32]byte{}) || m.Profile.Validate() != nil {
		return nil, ErrInvalidCommand
	}
	if _, err := s.factor.Envelope(); err != nil {
		return nil, ErrInvalidCommand
	}
	return []identity.FeatureField{{Name: "phone.reset.factor-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: m.FactorID}}, {Name: "phone.reset.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: m.EnrollmentVersion}}, {Name: "phone.reset.factor-authority-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: m.FactorAuthorityVersion}}}, nil
}

// Timeline returns the original selected database instant and absolute SMS
// expiry for the native owner's canonical grant bound. They are immutable
// structural metadata, not a fresh clock or permission. Zero returns no times;
// no IO, current check, renewal or credential disclosure occurs.
func (i PhonePasswordResetSendInput) Timeline() (issuedAt, expiresAt time.Time, err error) {
	if _, err := i.Fields(); err != nil {
		return time.Time{}, time.Time{}, err
	}
	r := i.state().record
	return r.issuedAt, r.expiresAt, nil
}

func (s *PhonePasswordResetIssuer) original(ctx context.Context, root identity.Command, input PhonePasswordResetSendInput, generation uint64) (phonePasswordResetSendInput, envelope.Context, error) {
	bad := func(err error) (phonePasswordResetSendInput, envelope.Context, error) {
		return phonePasswordResetSendInput{}, envelope.Context{}, err
	}
	p := s.state()
	if ctx == nil || p == nil || generation == 0 {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	i := input.state()
	spec, ok := root.Feature()
	if !ok || spec.Binding != i.binding || spec.Operation != phoneResetSendOperation() || len(spec.Fields) > 124 {
		return bad(ErrInvalidCommand)
	}
	fields, err := input.Fields()
	if err != nil {
		return bad(err)
	}
	seen := 0
	for _, actual := range spec.Fields {
		if otpField(actual.Name) {
			return bad(ErrInvalidCommand)
		}
		if strings.HasPrefix(actual.Name, "phone.reset.factor-") {
			matched := false
			for _, expected := range fields {
				if reflect.DeepEqual(actual, expected) {
					matched = true
					seen++
					break
				}
			}
			if !matched {
				return bad(ErrInvalidCommand)
			}
		}
	}
	if seen != len(fields) {
		return bad(ErrInvalidCommand)
	}
	if _, err := p.store.authenticateSendFlow(ctx, root, i.record.continuation, i.record.authority); err != nil {
		return bad(err)
	}
	wire, err := encodeSendRequestRecord(i.record, spec.Binding)
	if err != nil {
		return bad(err)
	}
	defer clear(wire)
	m, _ := i.factor.Metadata()
	sealed, _ := i.factor.Envelope()
	factorWire, err := sealed.MarshalBinary()
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	defer clear(factorWire)
	aad, err := phoneResetOriginalAAD(spec, wire, m, factorWire, p.configuration, generation)
	return i, aad, err
}

// Generate delegates actual SMS/code/digest/encrypted-delivery preparation only
// after the parent coordinator acknowledges generation start. It runs outside
// SQL and persists nothing. Retain its original output; never regenerate after
// ambiguity, unknown commit or a started generation without known output.
func (s *PhonePasswordResetIssuer) Generate(ctx context.Context, root identity.Command, input PhonePasswordResetSendInput, generation uint64) ([]byte, error) {
	i, aad, err := s.original(ctx, root, input, generation)
	if err != nil {
		return nil, err
	}
	return s.state().store.generatePreparedSend(ctx, root, i.record, generation, aad)
}

// PreparedPhonePasswordResetSend retains authenticated original native custody,
// not a scalar success verdict. Restore is its only producer. Copies are safe
// immutable borrows; no plaintext code/secret, transaction or resource is owned.
type PreparedPhonePasswordResetSend struct {
	read func() *preparedPhonePasswordResetSend
}
type preparedPhonePasswordResetSend struct {
	phase           *issuanceContributor
	generated, root identity.Command
	input           phonePasswordResetSendInput
	custody         issuanceCustody
	flow            nativeFlow
}

func (p PreparedPhonePasswordResetSend) state() *preparedPhonePasswordResetSend {
	if p.read == nil {
		return nil
	}
	return p.read()
}

// Restore authenticates exact input/configuration/factor ciphertext/generation,
// original cookie and retained IDOS1 output outside SQL. It restores the same
// delivery and digest without entropy, callbacks, new codes or renewed time.
func (s *PhonePasswordResetIssuer) Restore(ctx context.Context, root identity.Command, input PhonePasswordResetSendInput, generation uint64, wire []byte) (PreparedPhonePasswordResetSend, error) {
	i, aad, err := s.original(ctx, root, input, generation)
	if err != nil {
		return PreparedPhonePasswordResetSend{}, err
	}
	store := s.state().store
	spec, _ := root.Feature()
	cookie, _ := root.PreAuthCookie()
	phase, generated, err := restoreSendOutputContext(ctx, store, store.send.delivery, spec.Binding, generation, cookie, wire, aad)
	if err != nil {
		return PreparedPhonePasswordResetSend{}, err
	}
	custody, flow, err := store.authenticateIssuance(ctx, generated)
	if err != nil {
		return PreparedPhonePasswordResetSend{}, err
	}
	actual, _ := custody.challenge.Bindings()
	expected, err := encodeSendRequestRecord(i.record, spec.Binding)
	if err != nil {
		return PreparedPhonePasswordResetSend{}, err
	}
	defer clear(expected)
	got, err := encodeSendRequestRecord(sendRequestRecord{continuation: actual.Continuation, policy: actual.Policy, authority: custody.authority, recipient: custody.recipient, issuedAt: actual.IssuedAt, expiresAt: actual.ExpiresAt}, spec.Binding)
	defer clear(got)
	if err != nil || !bytes.Equal(expected, got) {
		return PreparedPhonePasswordResetSend{}, ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return PreparedPhonePasswordResetSend{}, err
	}
	p := &preparedPhonePasswordResetSend{phase: phase, generated: generated, root: root, input: i, custody: custody, flow: flow}
	return PreparedPhonePasswordResetSend{read: func() *preparedPhonePasswordResetSend { return p }}, nil
}

// Plan declares the original encrypted delivery in the parent's existing Work.
func (p PreparedPhonePasswordResetSend) Plan() (kernel.DeliveryPlan, error) {
	s := p.state()
	if s == nil {
		return kernel.DeliveryPlan{}, ErrInvalidCommand
	}
	return s.phase.prepared.Plan()
}

// Persist requires the exact registered native phone request and original root
// command. It independently locks current primary/password/pre-auth/recipient,
// then MFA user/aggregate/encrypted factor BEFORE shared OTP exclusions, applies
// existing SMS limits/challenge persistence and stages existing delivery in the
// same Work. Risk and canonical capability issuance remain the native phone
// owner's separate required effects. No crypto/provider/caller callback runs.
func (p PreparedPhonePasswordResetSend) Persist(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, root identity.Command) error {
	s := p.state()
	if ctx == nil || s == nil || root != s.root || owner == nil || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}) {
		return ErrInvalidCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, root); err != nil {
		return err
	}
	_, err := s.phase.applyPreparedIssuance(ctx, w, s.generated, owner, s)
	return err
}

// Recover contributes only the existing issuance tombstone vote to the parent's
// coordinator recovery. Unknown is never rolled back, replaced or re-compared.
func (s *PhonePasswordResetIssuer) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	p := s.state()
	if p == nil || owner == nil || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}) {
		return kernel.RecoveryUnknown, ErrInvalidCommand
	}
	b, f, _, err := w.FeatureScope(owner)
	if err != nil || f.Operation != phoneResetSendOperation() || b.ValidateFor(f.Operation) != nil {
		return kernel.RecoveryUnknown, ErrInvalidCommand
	}
	return (&issuanceContributor{store: p.store}).recoverIssuance(ctx, w, owner)
}

// Format omits keys, templates and native owner configuration.
func (PhonePasswordResetIssuerConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PhonePasswordResetIssuerConfig(redacted)"))
}

// Format omits the borrowed owners and retained key configuration.
func (*PhonePasswordResetIssuer) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PhonePasswordResetIssuer(redacted)"))
}

// Format omits original account, recipient, flow and factor custody.
func (PhonePasswordResetSendInput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PhonePasswordResetSendInput(redacted)"))
}

// Format omits original generated challenge and encrypted delivery custody.
func (PreparedPhonePasswordResetSend) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PreparedPhonePasswordResetSend(redacted)"))
}

// MarshalJSON rejects diagnostic configuration export.
func (PhonePasswordResetIssuerConfig) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText rejects diagnostic configuration export.
func (PhonePasswordResetIssuerConfig) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalJSON rejects native owner serialization.
func (*PhonePasswordResetIssuer) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText rejects native owner serialization.
func (*PhonePasswordResetIssuer) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalJSON rejects original request custody export.
func (PhonePasswordResetSendInput) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText rejects original request custody export.
func (PhonePasswordResetSendInput) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalJSON rejects generated request custody export.
func (PreparedPhonePasswordResetSend) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText rejects generated request custody export.
func (PreparedPhonePasswordResetSend) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

func phoneResetSendOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-request", SchemaID: "identity.phone.password-reset-request.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// Recovery is a sessionless, identifier-bound request, not an MFA login or an
// authenticated enrollment. Preserve its original policy and absolute lifetime.
func phoneResetSendFlow(b identity.CommandBinding, c otp.Continuation, issued, expires time.Time) bool {
	s, err := c.Bindings()
	if err != nil || s.RememberPolicy != (session.RememberPolicy{}) || s.Scope.PolicyVersion != b.PolicyVersion {
		return false
	}
	original, ok := s.Authorization.PreAuthTransaction()
	f, err := original.Bindings()
	return ok && err == nil && f.Binding.Intent.Purpose == session.PreAuthPhonePasswordRecovery &&
		f.Binding.Intent.Action == b.OperationID && f.Binding.Intent.TenantID == b.TenantID &&
		f.Binding.Intent.PolicyID == b.PolicyID && f.Binding.Intent.PolicyVersion == b.PolicyVersion &&
		f.Binding.Intent.IdentifierBinding != ([32]byte{}) && f.Binding.Intent.Remember == (session.RememberPolicy{}) &&
		!issued.Before(f.Binding.IssuedAt) && !expires.After(f.Binding.ExpiresAt)
}

func (s sendRequestRecord) validatePhoneResetSend(b identity.CommandBinding) error {
	c, err := s.continuation.Bindings()
	_, checks, pe := s.policy.Bindings()
	a := s.authority
	if err != nil || pe != nil || checks.Enabled || s.recipient == nil ||
		a.Credential.Kind != identity.CredentialPassword || a.Credential.Owner != "identity/password" ||
		c.Scope.TargetID != string(a.Credential.ID) ||
		s.recipient.UserAuthorityVersion != a.UserAuthorityVersion ||
		s.recipient.IdentifierAuthorityVersion != a.IdentifierAuthorityVersion ||
		s.recipient.CredentialAuthorityVersion != a.CredentialAuthorityVersion ||
		!phoneResetSendFlow(b, s.continuation, s.issuedAt, s.expiresAt) {
		return ErrInvalidCommand
	}
	return nil
}
