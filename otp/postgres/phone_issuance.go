package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// PhoneEnrollmentIssuerConfig selects consuming-only phone-verification SMS
// issuance using the ordinary OTP, session and encrypted delivery owners.
// It grants no workflow authority: the native phone service must enforce its
// original action-bound proof, session/CSRF, current factors and risk in Work.
// Dependencies are borrowed and must remain immutable throughout concurrent use.
type PhoneEnrollmentIssuerConfig struct {
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

// PhoneEnrollmentIssuer reuses normal OTP generation, digest custody, lockouts,
// send families and encrypted delivery. It owns no transaction, journal, timer
// or goroutine. Its methods are concurrent-safe; zero denies. Preparation is
// not delivery or verification and cannot manufacture a verified recipient.
type PhoneEnrollmentIssuer struct{ read func() *phoneEnrollmentIssuer }

// Closure custody prevents recursive fmt through an enclosing private field
// from bypassing the public Formatter and traversing borrowed crypto owners.
type phoneEnrollmentIssuer struct {
	store         *Contributor
	configuration [32]byte
	replacement   bool
}

func (s *PhoneEnrollmentIssuer) state() *phoneEnrollmentIssuer {
	if s == nil || s.read == nil {
		return nil
	}
	return s.read()
}

// NewPhoneEnrollmentIssuer freezes the separately closed SMS profile without
// IO, entropy or rendering. Install the selected OTP/session/delivery histories
// and Initialize before use. This constructor does not enable an HTTP feature.
func NewPhoneEnrollmentIssuer(c PhoneEnrollmentIssuerConfig) (*PhoneEnrollmentIssuer, error) {
	return newPhoneSMSIssuer(c, false)
}

func newPhoneSMSIssuer(c PhoneEnrollmentIssuerConfig, replacement bool) (*PhoneEnrollmentIssuer, error) {
	profile, checks, err := c.Policy.Bindings()
	if err != nil || profile.Purpose != otp.PurposePhoneVerification || checks.Enabled || c.Delivery == nil {
		return nil, ErrInvalidConfiguration
	}
	store, err := NewContributorWithSession(c.Store, c.Session)
	if err != nil {
		return nil, err
	}
	store, err = newPreparedSendContributor(store, c.Delivery, preparedSendConfig{
		preparation: otp.SendPreparationConfig{Policy: c.Policy, TemplateID: c.TemplateID, TemplateVersion: c.TemplateVersion, LocaleChain: c.LocaleChain},
		provider:    c.ProviderVersion, templates: c.Templates,
		contributors: []kernel.ContributorDescriptor{{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}, c.Delivery.Descriptor()},
	})
	if err != nil {
		return nil, err
	}
	profileID := "identity-otp-phone-enrollment-owner-v1\x00"
	if replacement {
		profileID = "identity-otp-phone-change-owner-v1\x00"
	}
	configuration, err := sessionIssuanceConfiguration(store, c.Session, c.Policy, profileID)
	if err != nil {
		return nil, err
	}
	p := &phoneEnrollmentIssuer{store: store, configuration: configuration, replacement: replacement}
	return &PhoneEnrollmentIssuer{read: func() *phoneEnrollmentIssuer { return p }}, nil
}

// Initialize binds existing retained OTP digest keys and stable lockout policy
// through bounded startup IO. Exact retry is idempotent; no schema, account,
// phone, challenge or session is created. The pool remains caller-owned.
func (s *PhoneEnrollmentIssuer) Initialize(ctx context.Context, pool *database.Pool) error {
	p := s.state()
	if p == nil || p.store == nil || p.store.codec == nil {
		return ErrInvalidConfiguration
	}
	return initializeIssuanceKeys(ctx, pool, p.store, p.store.codec.maximumDuration, p.store.codec.codeVersions)
}

// Configuration returns the immutable preparation identity, not a permission
// token. Preserve it with original request custody; it cannot renew freshness.
func (s *PhoneEnrollmentIssuer) Configuration() ([32]byte, error) {
	p := s.state()
	if p == nil || p.store == nil || p.configuration == ([32]byte{}) {
		return [32]byte{}, ErrInvalidConfiguration
	}
	return p.configuration, nil
}

// DeliveryContributor returns the exact borrowed delivery participant for the
// existing registry, not another queue, callback or transaction authority.
func (s *PhoneEnrollmentIssuer) DeliveryContributor() *deliverypg.Contributor {
	p := s.state()
	if p == nil || p.store == nil || p.store.send == nil {
		return nil
	}
	return p.store.send.delivery
}

// PhoneEnrollmentSendInput retains opaque original code-free native intent.
// CaptureInput is its sole public producer. It binds a new/unverified candidate,
// never a fabricated RecipientRecord, to the original real session, SMS purpose
// and command. Freeze it before acknowledged generation; zero denies. Closure
// custody protects ordinary diagnostics even under enclosing private fields.
type PhoneEnrollmentSendInput struct {
	read func() phoneEnrollmentSendInput
}

type phoneEnrollmentSendInput struct {
	Candidate           kernel.PhoneEnrollmentIntent
	replacement         *kernel.PhoneChangeIntent
	previous            *kernel.RecipientRecord
	Continuation        otp.Continuation
	Authority           AttemptAuthority
	IssuedAt, ExpiresAt time.Time
}

func newPhoneEnrollmentSendInput(i phoneEnrollmentSendInput) PhoneEnrollmentSendInput {
	return PhoneEnrollmentSendInput{read: func() phoneEnrollmentSendInput { return i }}
}

func (i PhoneEnrollmentSendInput) state() phoneEnrollmentSendInput {
	if i.read == nil {
		return phoneEnrollmentSendInput{}
	}
	return i.read()
}

// CaptureInput derives immutable original expectations from the real session
// returned by the action-primary owner. It performs no IO, current admission or
// generation. At must be the native request's original database instant; Until
// must already respect its action-proof deadline. This further caps the code
// lifetime by the original session expiry/freshness and selected OTP policy.
// Never pass an application-reconstructed session as authentication evidence;
// protected Persist independently checks the original stored session and epochs.
func (s *PhoneEnrollmentIssuer) CaptureInput(ctx context.Context, b identity.CommandBinding, candidate kernel.PhoneEnrollmentIntent, original session.Session, at, until time.Time) (PhoneEnrollmentSendInput, error) {
	if s.state() == nil || s.state().replacement {
		return PhoneEnrollmentSendInput{}, ErrInvalidCommand
	}
	return s.captureInput(ctx, b, phoneEnrollmentSendInput{Candidate: candidate}, original, at, until)
}

func (s *PhoneEnrollmentIssuer) captureInput(ctx context.Context, b identity.CommandBinding, input phoneEnrollmentSendInput, original session.Session, at, until time.Time) (PhoneEnrollmentSendInput, error) {
	p := s.state()
	op := phoneEnrollmentSendOperation()
	if p != nil && p.replacement {
		op = phoneChangeSendOperation()
	}
	if ctx == nil || p == nil || p.store == nil || p.store.session == nil || p.store.send == nil || b.ValidateFor(op) != nil ||
		p.replacement != (input.replacement != nil) ||
		!nativeTime(at) || !nativeTime(until) || !until.After(at) {
		return PhoneEnrollmentSendInput{}, ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return PhoneEnrollmentSendInput{}, err
	}
	d, c, a, err := sessionpg.OriginalSessionAdmission(p.store.session.profile, original, b)
	if err != nil || p.store.sessionTime(original, at) != nil {
		return PhoneEnrollmentSendInput{}, ErrInvalidCommand
	}
	authority := AttemptAuthority{Directory: d, Credential: c.Credential, UserAuthorization: a,
		UserAuthorityVersion: c.UserAuthorityVersion, IdentifierAuthorityVersion: c.IdentifierAuthorityVersion, CredentialAuthorityVersion: c.CredentialAuthorityVersion}
	flow, err := otp.NewBoundSessionAuthorization(original)
	if err != nil {
		return PhoneEnrollmentSendInput{}, ErrInvalidCommand
	}
	change, err := input.change()
	if err != nil {
		return PhoneEnrollmentSendInput{}, err
	}
	destination, err := otp.NewDestinationInput(change.CanonicalValue)
	if err != nil {
		return PhoneEnrollmentSendInput{}, ErrInvalidCommand
	}
	continuation, err := otp.NewContinuation(otp.DigestScopeSpec{TenantID: string(b.TenantID), SubjectID: string(b.UserID), Purpose: otp.PurposePhoneVerification,
		Channel: otp.ChannelSMS, Destination: destination, ChallengeID: string(b.CommandID), TargetID: string(change.ID), PolicyVersion: b.PolicyVersion, Generation: 1}, flow, session.RememberPolicy{})
	if err != nil {
		return PhoneEnrollmentSendInput{}, ErrInvalidCommand
	}
	profile, _, _ := p.store.send.policy.Bindings()
	lifetime, err := original.Lifetime(at)
	if err != nil {
		return PhoneEnrollmentSendInput{}, ErrInvalidCommand
	}
	origin, _ := original.Bindings()
	for _, bound := range []time.Time{at.Add(profile.TTL), lifetime.ExpiresAt, origin.Authentication.Proof.IssuedAt.Add(p.store.session.freshness)} {
		if bound.Before(until) {
			until = bound.UTC().Truncate(time.Microsecond)
		}
	}
	input.Continuation, input.Authority, input.IssuedAt, input.ExpiresAt = continuation, authority, at, until
	retained := newPhoneEnrollmentSendInput(input)
	if _, err := retained.record(p.store.send.policy, b); err != nil {
		return PhoneEnrollmentSendInput{}, err
	}
	if err := ctx.Err(); err != nil {
		return PhoneEnrollmentSendInput{}, err
	}
	return retained, nil
}

func (i PhoneEnrollmentSendInput) record(policy otp.AttemptPolicy, b identity.CommandBinding) (sendRequestRecord, error) {
	s := i.state()
	c, err := s.Continuation.Bindings()
	if err != nil {
		return sendRequestRecord{}, ErrInvalidCommand
	}
	change, err := s.change()
	if err != nil {
		return sendRequestRecord{}, ErrInvalidCommand
	}
	if change.TenantID != b.TenantID || change.UserID != b.UserID || string(change.ID) != c.Scope.TargetID || change.CanonicalValue != c.Scope.Destination.Value() || change.ExpectedAuthorityVersion != s.Authority.IdentifierAuthorityVersion {
		return sendRequestRecord{}, ErrInvalidCommand
	}
	if s.replacement == nil && string(change.ID) != b.RecordID ||
		s.replacement != nil && (b.RecordID != string(b.CommandID) || s.replacement.SendCommandID != b.CommandID || !s.previousMatches()) {
		return sendRequestRecord{}, ErrInvalidCommand
	}
	r := sendRequestRecord{continuation: s.Continuation, policy: policy, authority: s.Authority, issuedAt: s.IssuedAt, expiresAt: s.ExpiresAt}
	if err := r.validate(b); err != nil {
		return sendRequestRecord{}, err
	}
	return r, nil
}

func (s *PhoneEnrollmentIssuer) original(ctx context.Context, root identity.Command, input PhoneEnrollmentSendInput, generation uint64) (sendRequestRecord, envelope.Context, error) {
	bad := func(err error) (sendRequestRecord, envelope.Context, error) {
		return sendRequestRecord{}, envelope.Context{}, err
	}
	p := s.state()
	if ctx == nil || p == nil || p.store == nil || p.store.send == nil || generation == 0 {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	spec, ok := root.Feature()
	op, prefix, profile := phoneEnrollmentSendOperation(), "phone-enrollment.", "identity-otp-phone-enrollment-send-v1"
	if p.replacement {
		op, prefix, profile = phoneChangeSendOperation(), "phone-change.", "identity-otp-phone-change-send-v1"
	}
	if !ok || spec.Operation != op || p.replacement != (input.state().replacement != nil) {
		return bad(ErrInvalidCommand)
	}
	fields, err := input.state().fields()
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	seen := make(map[string]bool, len(fields))
	for _, actual := range spec.Fields {
		if otpField(actual.Name) {
			return bad(ErrInvalidCommand)
		}
		if !strings.HasPrefix(actual.Name, prefix) {
			continue
		}
		if seen[actual.Name] {
			return bad(ErrInvalidCommand)
		}
		found := false
		for _, expected := range fields {
			if actual.Name == expected.Name {
				if !reflect.DeepEqual(actual, expected) {
					return bad(ErrInvalidCommand)
				}
				seen[actual.Name], found = true, true
				break
			}
		}
		if !found {
			return bad(ErrInvalidCommand)
		}
	}
	if len(seen) != len(fields) {
		return bad(ErrInvalidCommand)
	}
	record, err := input.record(p.store.send.policy, spec.Binding)
	if err != nil {
		return bad(err)
	}
	if _, err := p.store.authenticateSendFlow(ctx, root, record.continuation, record.authority); err != nil {
		return bad(err)
	}
	wire, err := encodeSendRequestRecord(record, spec.Binding)
	if err != nil {
		return bad(err)
	}
	defer clear(wire)
	if p.replacement {
		// The old recipient is not the new SMS destination and must not enter
		// OTP's verified-destination slot. Bind its independent exact snapshot
		// into this new profile's authenticated output instead. Keep existing
		// enrollment framing byte-for-byte unchanged for retained commands.
		previous := appendSendRecipient(nil, *input.state().previous)
		wrapped := appendAuthorityText([]byte("identity-phone-change-send-input-v1\x00"), string(wire))
		clear(wire)
		wire = appendAuthorityText(wrapped, string(previous))
		clear(previous)
		defer clear(wire)
	}
	frame, err := json.Marshal(struct {
		Binding       identity.CommandBinding
		Operation     identity.FeatureOperation
		Fields        []identity.FeatureField
		Input         []byte
		Configuration [32]byte
		Generation    uint64
	}{spec.Binding, spec.Operation, spec.Fields, wire, p.configuration, generation})
	if err != nil || len(frame) > 32768 {
		clear(frame)
		return bad(ErrInvalidCommand)
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	aad, err := envelope.NewContext(map[string]string{"profile": profile, "binding": base64.RawURLEncoding.EncodeToString(digest[:]), "generation": strconv.FormatUint(generation, 10)})
	return record, aad, err
}

// Generate delegates to OTP's sole generator only after the owning coordinator
// acknowledges its preparation-generation marker. It persists nothing. Never
// regenerate an uncertain or retained output: restore the original checkpoint.
func (s *PhoneEnrollmentIssuer) Generate(ctx context.Context, root identity.Command, input PhoneEnrollmentSendInput, generation uint64) ([]byte, error) {
	record, aad, err := s.original(ctx, root, input, generation)
	if err != nil {
		return nil, err
	}
	return s.state().store.generatePreparedSend(ctx, root, record, generation, aad)
}

// PreparedPhoneEnrollmentSend is immutable original digest/encrypted-delivery
// custody. It cannot compare an OTP, verify a phone or authorize its own Work.
// Copies share immutable values. Zero denies and implicit diagnostics redact.
type PreparedPhoneEnrollmentSend struct {
	read func() *preparedPhoneEnrollmentSend
}

type preparedPhoneEnrollmentSend struct {
	phase     *issuanceContributor
	generated identity.Command
	root      identity.FeatureCommandSpec
	candidate kernel.PhoneEnrollmentIntent
	previous  *kernel.RecipientRecord
}

func (p PreparedPhoneEnrollmentSend) state() *preparedPhoneEnrollmentSend {
	if p.read == nil {
		return nil
	}
	return p.read()
}

// Restore conserves the same digest, encrypted SMS, original session, candidate,
// configuration and generation without IO, entropy or freshness renewal.
func (s *PhoneEnrollmentIssuer) Restore(ctx context.Context, root identity.Command, input PhoneEnrollmentSendInput, generation uint64, wire []byte) (PreparedPhoneEnrollmentSend, error) {
	record, aad, err := s.original(ctx, root, input, generation)
	if err != nil {
		return PreparedPhoneEnrollmentSend{}, err
	}
	spec, _ := root.Feature()
	bearer, _ := root.SessionToken()
	store := s.state().store
	phase, generated, err := restoreSendOutputContext(ctx, store, store.send.delivery, spec.Binding, generation, bearer, wire, aad)
	if err != nil {
		return PreparedPhoneEnrollmentSend{}, err
	}
	custody, _, err := store.authenticateIssuance(ctx, generated)
	if err != nil || custody.recipient != nil {
		return PreparedPhoneEnrollmentSend{}, ErrInvalidCommand
	}
	actual, _ := custody.challenge.Bindings()
	expected, err := encodeSendRequestRecord(record, spec.Binding)
	if err != nil {
		return PreparedPhoneEnrollmentSend{}, err
	}
	defer clear(expected)
	got, err := encodeSendRequestRecord(sendRequestRecord{continuation: actual.Continuation, policy: actual.Policy, authority: custody.authority, issuedAt: actual.IssuedAt, expiresAt: actual.ExpiresAt}, spec.Binding)
	defer clear(got)
	if err != nil || !reflect.DeepEqual(got, expected) {
		return PreparedPhoneEnrollmentSend{}, ErrInvalidCommand
	}
	p := &preparedPhoneEnrollmentSend{phase: phase, generated: generated, root: spec, candidate: input.state().Candidate, previous: input.state().previous}
	return PreparedPhoneEnrollmentSend{read: func() *preparedPhoneEnrollmentSend { return p }}, nil
}

// Plan returns an owned declaration of the sole original encrypted SMS. Enlist
// this exact delivery participant/plan in the owning coordinator transaction.
func (p PreparedPhoneEnrollmentSend) Plan() (kernel.DeliveryPlan, error) {
	state := p.state()
	if state == nil || state.phase == nil {
		return kernel.DeliveryPlan{}, ErrInvalidCommand
	}
	return state.phase.prepared.Plan()
}

// Persist requires the exact kernel-prepared phone candidate and original native
// command during the registered phone owner's Apply. The native caller must
// enforce action proof, current session/CSRF/factors and risk first, propagate
// every error and conserve original validity at final commit. No private
// transaction, verification fact, code generation or session is created here.
func (p PreparedPhoneEnrollmentSend) Persist(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, root identity.Command) error {
	state := p.state()
	if state == nil || state.phase == nil || owner == nil {
		return ErrInvalidCommand
	}
	spec, ok := root.Feature()
	if !ok || !reflect.DeepEqual(spec, state.root) {
		return ErrInvalidCommand
	}
	if state.previous != nil {
		if err := w.RequireRecipient(ctx, owner, *state.previous); err != nil {
			return err
		}
	} else {
		if err := w.RequirePhoneEnrollmentCandidate(ctx, owner, root, state.candidate); err != nil {
			return err
		}
	}
	_, err := state.phase.applyIssuance(ctx, w, state.generated, owner)
	return err
}

// Recover contributes only the original native issuance tombstone vote. It
// compares no code, renews no authority and reconstructs no success receipt.
func (s *PhoneEnrollmentIssuer) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	p := s.state()
	if p == nil || p.store == nil {
		return kernel.RecoveryUnknown, ErrInvalidCommand
	}
	return (&issuanceContributor{store: p.store}).recoverIssuance(ctx, w, owner)
}

// Format redacts credentials and borrowed crypto ownership.
func (PhoneEnrollmentIssuerConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PhoneEnrollmentIssuerConfig(redacted)"))
}

// MarshalJSON denies implicit key export.
func (PhoneEnrollmentIssuerConfig) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// Format redacts borrowed ownership.
func (PhoneEnrollmentIssuer) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PhoneEnrollmentIssuer(redacted)"))
}

// MarshalJSON denies implicit owner export.
func (PhoneEnrollmentIssuer) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// Format redacts original candidate and authority.
func (PhoneEnrollmentSendInput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PhoneEnrollmentSendInput(redacted)"))
}

// MarshalJSON denies implicit correlated input export.
func (PhoneEnrollmentSendInput) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// Format redacts retained challenge/delivery custody.
func (PreparedPhoneEnrollmentSend) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PreparedPhoneEnrollmentSend(redacted)"))
}

// MarshalJSON denies implicit encrypted custody export.
func (PreparedPhoneEnrollmentSend) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}
