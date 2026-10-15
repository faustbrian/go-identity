package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"time"

	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
)

// MFAEnrollmentIssuerConfig selects the existing OTP generation/store and
// delivery owners for MFA's authenticated pending-enrollment operation. It
// supplies no coordinator, journal, risk-clearance callback or primary override.
// The actual MFA owner must enforce original parent/session/CSRF/factor/risk
// admission in its Work. Store.Codec and Delivery are immutable borrowed owners.
// Install the ordinary OTP/send-family/issuance and delivery histories first.
type MFAEnrollmentIssuerConfig struct {
	Store           ContributorConfig
	Session         SessionAdmissionConfig
	Delivery        *deliverypg.Contributor
	Policy          otp.AttemptPolicy
	TemplateID      string
	TemplateVersion uint32
	ProviderVersion uint64
	LocaleChain     []string
	Templates       []delivery.Template
}

// MFAEnrollmentIssuer reuses the sole OTP generator, custody codec, shared
// send-family/lockout store and delivery contributor. It owns no pool, timer,
// goroutine, transaction or command authority and cannot authenticate an MFA
// factor. Inputs and dependencies must remain immutable during calls.
type MFAEnrollmentIssuer struct {
	store         *Contributor
	configuration [32]byte
}

var _ mfapg.OTPEnrollmentIssuanceOwner = (*MFAEnrollmentIssuer)(nil)

// Initialize registers the same stable lockout binding and retained digest-key
// metadata as ordinary native Send. It runs only bounded startup IO, not schema
// installation or a business mutation. Exact retry is idempotent; changed keys
// deny and lost commit acknowledgement remains unavailable. Pool is borrowed.
func (s *MFAEnrollmentIssuer) Initialize(ctx context.Context, pool *database.Pool) error {
	if s == nil || s.store == nil || s.store.codec == nil {
		return ErrInvalidConfiguration
	}
	return initializeIssuanceKeys(ctx, pool, s.store, s.store.codec.maximumDuration, s.store.codec.codeVersions)
}

// PrepareEnrollmentSend implements MFA's native port. The returned original
// record has no code or submitted bearer; MFA must retain it under its existing
// encrypted request-key custody before any generation callback.
func (s *MFAEnrollmentIssuer) PrepareEnrollmentSend(ctx context.Context, pool *database.Pool, binding identity.CommandBinding, original session.Session, recipient kernel.RecipientRecord, at, until time.Time) ([]byte, error) {
	input, err := s.CaptureInput(ctx, pool, binding, original, recipient, at, until)
	if err != nil {
		return nil, err
	}
	record, err := input.record(s.store.send.policy, binding)
	if err != nil {
		return nil, err
	}
	return encodeSendRequestRecord(record, binding)
}

func (s *MFAEnrollmentIssuer) restoreEnrollmentInput(root identity.Command, wire []byte) (MFAEnrollmentSendInput, error) {
	if s == nil || s.store == nil {
		return MFAEnrollmentSendInput{}, ErrInvalidCommand
	}
	spec, ok := root.Feature()
	if !ok || spec.Operation != mfaEnrollmentSendOperation() {
		return MFAEnrollmentSendInput{}, ErrInvalidCommand
	}
	record, err := decodeSendRequestRecord(wire, spec.Binding)
	if err != nil || record.recipient == nil || !sameSendPolicy(record.policy, s.store.send.policy) {
		return MFAEnrollmentSendInput{}, ErrInvalidCommand
	}
	return MFAEnrollmentSendInput{Continuation: record.continuation, Authority: record.authority, Recipient: *record.recipient, IssuedAt: record.issuedAt, ExpiresAt: record.expiresAt}, nil
}

// GenerateEnrollmentSend delegates only acknowledged native MFA preparation to
// the ordinary OTP generator. Authenticated original input grants no live Allow.
func (s *MFAEnrollmentIssuer) GenerateEnrollmentSend(ctx context.Context, root identity.Command, wire []byte, generation uint64) ([]byte, error) {
	input, err := s.restoreEnrollmentInput(root, wire)
	if err != nil {
		return nil, err
	}
	return s.Generate(ctx, root, input, generation)
}

// RestoreEnrollmentSend implements the same-code native MFA checkpoint port,
// returning an opaque effect without generation or independent persistence.
func (s *MFAEnrollmentIssuer) RestoreEnrollmentSend(ctx context.Context, root identity.Command, inputWire []byte, generation uint64, output []byte) (mfapg.OTPEnrollmentPreparedSend, error) {
	input, err := s.restoreEnrollmentInput(root, inputWire)
	if err != nil {
		return nil, err
	}
	return s.Restore(ctx, root, input, generation, output)
}

// CaptureInput reads native current authority outside protected locks and binds
// it to the supplied original session and verified recipient. It grants no
// admission: Persist independently fences the same versions. Pool is borrowed;
// no transaction, code or journal is created. At is the original database
// instant and Until cannot exceed the original pending ceremony's lifetime.
func (s *MFAEnrollmentIssuer) CaptureInput(ctx context.Context, pool *database.Pool, binding identity.CommandBinding, original session.Session, recipient kernel.RecipientRecord, at, until time.Time) (MFAEnrollmentSendInput, error) {
	if ctx == nil || s == nil || s.store == nil || s.store.session == nil || pool == nil || pool.Raw() == nil {
		return MFAEnrollmentSendInput{}, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, s.store.codec.maximumDuration)
	defer stop()
	op, err := boundIssuanceOperation(binding)
	if err != nil || op != mfaEnrollmentSendOperation() || recipient.Validate() != nil || recipient.Suppressed {
		return MFAEnrollmentSendInput{}, ErrInvalidCommand
	}
	repo, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: s.store.codec.maximumDuration})
	if err != nil {
		return MFAEnrollmentSendInput{}, err
	}
	authz, err := authoritypg.NewAuthorityStore(pool.Raw(), s.store.codec.maximumDuration)
	if err != nil {
		return MFAEnrollmentSendInput{}, err
	}
	reader := *s.store
	reader.initiation = &sendInitiationProfile{pool: pool, kernel: repo, authorization: authz}
	a, err := reader.readInitiatingAuthority(ctx, binding)
	if err != nil {
		return MFAEnrollmentSendInput{}, err
	}
	_, credential, _, err := sessionpg.OriginalSessionAdmission(s.store.session.profile, original, binding)
	if err != nil {
		return MFAEnrollmentSendInput{}, ErrInvalidCommand
	}
	a.Credential = credential.Credential
	if s.store.sessionAuthority(original, binding, a) != nil {
		return MFAEnrollmentSendInput{}, ErrInvalidCommand
	}
	flow, err := otp.NewBoundSessionAuthorization(original)
	if err != nil {
		return MFAEnrollmentSendInput{}, err
	}
	channel := otp.ChannelEmail
	if recipient.Identifier.Kind == identity.IdentifierPhone {
		channel = otp.ChannelSMS
	}
	destination, err := otp.NewDestinationInput(recipient.Identifier.CanonicalValue)
	if err != nil {
		return MFAEnrollmentSendInput{}, err
	}
	continuation, err := otp.NewContinuation(otp.DigestScopeSpec{TenantID: string(binding.TenantID), SubjectID: string(binding.UserID), Purpose: otp.PurposeMFA, Channel: channel, Destination: destination, ChallengeID: string(binding.CommandID), TargetID: binding.RecordID, PolicyVersion: binding.PolicyVersion, Generation: 1}, flow, session.RememberPolicy{})
	if err != nil {
		return MFAEnrollmentSendInput{}, err
	}
	profile, _, _ := s.store.send.policy.Bindings()
	if end := at.Add(profile.TTL); end.Before(until) {
		until = end
	}
	input := MFAEnrollmentSendInput{Continuation: continuation, Authority: a, Recipient: recipient, IssuedAt: at, ExpiresAt: until}
	if _, err := input.record(s.store.send.policy, binding); err != nil {
		return MFAEnrollmentSendInput{}, err
	}
	return input, nil
}

// Configuration returns the immutable non-secret preparation identity for the
// MFA owner's original configuration binding. It is not an admission token.
func (s *MFAEnrollmentIssuer) Configuration() ([32]byte, error) {
	if s == nil || s.store == nil || s.store.send == nil || s.configuration == ([32]byte{}) {
		return [32]byte{}, ErrInvalidConfiguration
	}
	return s.configuration, nil
}

// RecoverEnrollmentSend contributes a native tombstone vote without code,
// primary restoration or generation. Retained issuance prevents a negative
// outcome; only the existing journal can establish the committed receipt.
func (s *MFAEnrollmentIssuer) RecoverEnrollmentSend(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if s == nil || s.store == nil {
		return kernel.RecoveryUnknown, ErrInvalidCommand
	}
	return (&issuanceContributor{store: s.store}).recoverIssuance(ctx, w, owner)
}

// NewMFAEnrollmentIssuer freezes an explicitly selected native profile without
// IO or generation. MFA-purpose consuming-only challenges are required; an
// ordinary signin/check deployment cannot silently become enrollment issuance.
func NewMFAEnrollmentIssuer(c MFAEnrollmentIssuerConfig) (*MFAEnrollmentIssuer, error) {
	profile, checks, err := c.Policy.Bindings()
	if err != nil || profile.Purpose != otp.PurposeMFA || checks.Enabled || c.Delivery == nil {
		return nil, ErrInvalidConfiguration
	}
	store, err := NewContributorWithSession(c.Store, c.Session)
	if err != nil {
		return nil, err
	}
	store, err = newPreparedSendContributor(store, c.Delivery, preparedSendConfig{
		preparation: otp.SendPreparationConfig{Policy: c.Policy, TemplateID: c.TemplateID, TemplateVersion: c.TemplateVersion, LocaleChain: c.LocaleChain},
		provider:    c.ProviderVersion, templates: c.Templates,
		contributors: []kernel.ContributorDescriptor{{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}, c.Delivery.Descriptor()},
	})
	if err != nil {
		return nil, err
	}
	frame := append([]byte("identity-otp-mfa-enrollment-owner-v1\x00"), store.send.configuration[:]...)
	frame = append(frame, store.codec.configuration[:]...)
	lockout := store.lockout.binding()
	frame = append(frame, lockout[:]...)
	for _, value := range []string{store.schema, store.global, store.namespace, c.Session.Store.Schema, c.Session.Profile.GlobalAuthorityID, c.Session.Profile.PolicyNamespace, c.Session.Profile.Audience, c.Session.Profile.AuthenticationMethod, c.Session.Profile.CredentialOwner} {
		frame = appendAuthorityText(frame, value)
	}
	frame = binary.BigEndian.AppendUint64(frame, uint64(c.Session.Store.MaximumDuration))
	frame = binary.BigEndian.AppendUint64(frame, uint64(c.Session.FreshnessLimit))
	frame = append(frame, byte(c.Session.Profile.CredentialKind))
	versions := make([]uint32, 0, len(c.Session.RetainedTokenKeys))
	for version := range c.Session.RetainedTokenKeys {
		versions = append(versions, version)
	}
	slices.Sort(versions)
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(versions)))
	for _, version := range versions {
		frame = binary.BigEndian.AppendUint32(frame, version)
		frame = binary.BigEndian.AppendUint32(frame, uint32(len(c.Session.RetainedTokenKeys[version])))
		frame = append(frame, c.Session.RetainedTokenKeys[version]...)
	}
	policy, err := json.Marshal(struct {
		Profile otp.CodeProfileSpec
		Checks  otp.CheckPolicySpec
	}{profile, checks})
	if err != nil {
		clear(frame)
		return nil, ErrInvalidConfiguration
	}
	frame = append(frame, policy...)
	clear(policy)
	configuration := sha256.Sum256(frame)
	clear(frame)
	return &MFAEnrollmentIssuer{store: store, configuration: configuration}, nil
}

// MFAEnrollmentSendInput is trusted original code-free preparation, not client
// JSON or authentication evidence. Continuation must bind the actual original
// session, MFA purpose, target factor and server-issued challenge command ID.
// The native MFA owner supplies real recipient/authority projections and freezes
// these exact values in its original encrypted request before generation.
type MFAEnrollmentSendInput struct {
	Continuation        otp.Continuation
	Authority           AttemptAuthority
	Recipient           kernel.RecipientRecord
	IssuedAt, ExpiresAt time.Time
}

func (i MFAEnrollmentSendInput) record(policy otp.AttemptPolicy, binding identity.CommandBinding) (sendRequestRecord, error) {
	if i.Recipient.Suppressed || i.Recipient.Query.Eligibility != kernel.RecipientVerified {
		return sendRequestRecord{}, ErrInvalidCommand
	}
	r := sendRequestRecord{continuation: i.Continuation, policy: policy, authority: i.Authority, recipient: &i.Recipient, issuedAt: i.IssuedAt, expiresAt: i.ExpiresAt}
	if err := r.validate(binding); err != nil {
		return sendRequestRecord{}, err
	}
	return r, nil
}

func (s *MFAEnrollmentIssuer) original(ctx context.Context, root identity.Command, input MFAEnrollmentSendInput, generation uint64) (sendRequestRecord, envelope.Context, error) {
	if s == nil || s.store == nil || s.store.send == nil {
		return sendRequestRecord{}, envelope.Context{}, ErrInvalidCommand
	}
	return originalMFASend(ctx, s.store, root, input, generation, mfaEnrollmentSendOperation(), "identity-otp-mfa-enrollment-send-v1", s.store.send.configuration)
}

func originalMFASend(ctx context.Context, store *Contributor, root identity.Command, input MFAEnrollmentSendInput, generation uint64, operation identity.FeatureOperation, profile string, configuration [32]byte) (sendRequestRecord, envelope.Context, error) {
	bad := func(err error) (sendRequestRecord, envelope.Context, error) {
		return sendRequestRecord{}, envelope.Context{}, err
	}
	if ctx == nil || store == nil || store.send == nil || generation == 0 {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	spec, ok := root.Feature()
	op, err := boundIssuanceOperation(spec.Binding)
	if !ok || err != nil || op != operation || spec.Operation != op || len(spec.Fields) > 124 {
		return bad(ErrInvalidCommand)
	}
	parent := ""
	for _, field := range spec.Fields {
		if otpField(field.Name) {
			return bad(ErrInvalidCommand)
		}
		if field.Name == "factor.parent-command" {
			if parent != "" || field.Value.Kind != identity.FeatureText {
				return bad(ErrInvalidCommand)
			}
			parent = field.Value.Text
		}
	}
	if _, err := identity.ParseCommandID(parent); err != nil || parent == string(spec.Binding.CommandID) || parent == spec.Binding.RecordID {
		return bad(ErrInvalidCommand)
	}
	if operation == mfaLoginSendOperation() {
		b, err := input.Continuation.Bindings()
		if err != nil {
			return bad(ErrInvalidCommand)
		}
		_, correlation, ok := b.Authorization.MFAContinuation()
		if !ok || parent != string(correlation.PrimaryCommandID) {
			return bad(ErrInvalidCommand)
		}
	}
	record, err := input.record(store.send.policy, spec.Binding)
	if err != nil {
		return bad(err)
	}
	if _, err := store.authenticateSendFlow(ctx, root, record.continuation, record.authority); err != nil {
		return bad(err)
	}
	wire, err := encodeSendRequestRecord(record, spec.Binding)
	if err != nil {
		return bad(err)
	}
	defer clear(wire)
	// Explicit transient metadata serialization includes every static owner
	// field and complete original recipient/session/authority declaration. No
	// submitted bearer or generated code enters either the frame or ciphertext.
	frame, err := json.Marshal(struct {
		Binding       identity.CommandBinding
		Operation     identity.FeatureOperation
		Fields        []identity.FeatureField
		Input         []byte
		Configuration [32]byte
		Generation    uint64
	}{spec.Binding, spec.Operation, spec.Fields, wire, configuration, generation})
	if err != nil || len(frame) > 32768 {
		clear(frame)
		return bad(ErrInvalidCommand)
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	aad, err := envelope.NewContext(map[string]string{"profile": profile, "binding": base64.RawURLEncoding.EncodeToString(digest[:]), "generation": strconv.FormatUint(generation, 10)})
	return record, aad, err
}

// Generate must be invoked only by the real MFA participant after the existing
// coordinator acknowledges its generation-start marker. It generates one code
// with OTP's normal preparer and retains the matching digest/encrypted delivery
// in the existing preparation output. It grants no admission and persists
// nothing. Never call it to replace original uncertain or retained output.
func (s *MFAEnrollmentIssuer) Generate(ctx context.Context, root identity.Command, input MFAEnrollmentSendInput, generation uint64) ([]byte, error) {
	record, aad, err := s.original(ctx, root, input, generation)
	if err != nil {
		return nil, err
	}
	return s.store.generatePreparedSend(ctx, root, record, generation, aad)
}

// PreparedMFAEnrollmentSend is opaque original issuance/delivery custody. Copies
// share immutable retained bytes. It cannot compare a code, consume an MFA child,
// activate a factor, issue a session or authorize its own Work. Zero denies.
type PreparedMFAEnrollmentSend struct {
	issuer    *MFAEnrollmentIssuer
	phase     *issuanceContributor
	generated identity.Command
	root      identity.FeatureCommandSpec
}

// Restore conserves the exact original output without generation, encryption,
// freshness renewal or IO. A changed parent, static intent, recipient, profile,
// configuration, generation or bearer denies. Current native guards remain
// mandatory when this effect is later persisted.
func (s *MFAEnrollmentIssuer) Restore(ctx context.Context, root identity.Command, input MFAEnrollmentSendInput, generation uint64, wire []byte) (PreparedMFAEnrollmentSend, error) {
	record, aad, err := s.original(ctx, root, input, generation)
	if err != nil {
		return PreparedMFAEnrollmentSend{}, err
	}
	spec, _ := root.Feature()
	bearer, _ := root.SessionToken()
	phase, generated, err := restoreSendOutputContext(ctx, s.store, s.store.send.delivery, spec.Binding, generation, bearer, wire, aad)
	if err != nil {
		return PreparedMFAEnrollmentSend{}, err
	}
	custody, _, err := s.store.authenticateIssuance(ctx, generated)
	if err != nil {
		return PreparedMFAEnrollmentSend{}, err
	}
	actual, _ := custody.challenge.Bindings()
	expected, err := encodeSendRequestRecord(record, spec.Binding)
	if err != nil {
		return PreparedMFAEnrollmentSend{}, err
	}
	defer clear(expected)
	got, err := encodeSendRequestRecord(sendRequestRecord{continuation: actual.Continuation, policy: actual.Policy, authority: custody.authority, issuedAt: actual.IssuedAt, expiresAt: actual.ExpiresAt, recipient: custody.recipient}, spec.Binding)
	defer clear(got)
	if err != nil || !reflect.DeepEqual(got, expected) {
		return PreparedMFAEnrollmentSend{}, ErrInvalidCommand
	}
	return PreparedMFAEnrollmentSend{issuer: s, phase: phase, generated: generated, root: spec}, nil
}

// Plan returns an owned declaration of the sole original encrypted delivery.
// The MFA coordinator must enlist this exact real contributor and plan.
func (p PreparedMFAEnrollmentSend) Plan() (kernel.DeliveryPlan, error) {
	if p.phase == nil {
		return kernel.DeliveryPlan{}, ErrInvalidCommand
	}
	return p.phase.prepared.Plan()
}

// DeliveryContributor exposes the actual immutable participant for the caller's
// existing registry, not an additional queue or transaction authority.
func (s *MFAEnrollmentIssuer) DeliveryContributor() *deliverypg.Contributor {
	if s == nil || s.store == nil || s.store.send == nil {
		return nil
	}
	return s.store.send.delivery
}

// Persist appends the challenge and stages its original delivery only in the
// actual registered MFA owner's Work. Require original parent/session/CSRF,
// current pending factor/recipient and protected risk before calling; recheck
// them after its waits and before commit. Return every error to the coordinator.
// No transaction, journal, code generation or session is created here.
func (p PreparedMFAEnrollmentSend) Persist(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, root identity.Command) error {
	if p.phase == nil || owner == nil || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) {
		return ErrInvalidCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, root); err != nil {
		return err
	}
	spec, ok := root.Feature()
	if !ok || !reflect.DeepEqual(spec, p.root) {
		return ErrInvalidCommand
	}
	_, err := p.phase.applyIssuance(ctx, w, p.generated, owner)
	return err
}

// Format redacts borrowed configuration and crypto ownership.
func (MFAEnrollmentIssuerConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.MFAEnrollmentIssuerConfig(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (MFAEnrollmentIssuerConfig) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText denies implicit configuration export.
func (MFAEnrollmentIssuerConfig) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// Format redacts original preparation.
func (MFAEnrollmentSendInput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.MFAEnrollmentSendInput(redacted)"))
}

// MarshalJSON denies implicit original preparation export.
func (MFAEnrollmentSendInput) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText denies implicit original preparation export.
func (MFAEnrollmentSendInput) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// Format redacts encrypted issuance ownership.
func (PreparedMFAEnrollmentSend) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PreparedMFAEnrollmentSend(redacted)"))
}

// MarshalJSON denies implicit custody export.
func (PreparedMFAEnrollmentSend) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText denies implicit custody export.
func (PreparedMFAEnrollmentSend) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// Format redacts borrowed native owners.
func (MFAEnrollmentIssuer) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.MFAEnrollmentIssuer(redacted)"))
}

// MarshalJSON denies implicit issuer export.
func (MFAEnrollmentIssuer) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText denies implicit issuer export.
func (MFAEnrollmentIssuer) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
