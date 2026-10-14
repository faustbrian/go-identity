package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
)

// MFALoginIssuerConfig selects native secondary-OTP generation/delivery under
// an original consumed browser primary. Store must include its actual pre-auth
// cookie keys and history, not authenticated-session admission. Consumers must
// supply the native MFA service, not application-written factor/risk stores.
// All configuration and borrowed owners must be immutable during calls.
type MFALoginIssuerConfig struct {
	Store           ContributorConfig
	Delivery        *deliverypg.Contributor
	Policy          otp.AttemptPolicy
	TemplateID      string
	TemplateVersion uint32
	ProviderVersion uint64
	LocaleChain     []string
	Templates       []delivery.Template
}

// MFALoginIssuer uses the existing OTP generator, send limits, encrypted delivery
// and journal output grammar. It never authenticates a child, selects a factor,
// resets attempts, consumes primary/child custody or issues a session. Concurrent
// calls require immutable original input. No pool, goroutine or transaction is owned.
type MFALoginIssuer struct {
	store         *Contributor
	configuration [32]byte
}

// CompletionContributor returns this issuer's actual native OTP consuming and
// recovery owner for explicit MFA composition, without IO or challenge custody.
// Enlist it in the sole coordinator; it cannot authenticate a child, compare a
// code or issue a session outside the registered native phases. Zero returns nil.
func (s *MFALoginIssuer) CompletionContributor() kernel.OTPExecutionContributor {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store
}

// NewMFALoginIssuer freezes the disjoint MFA partial-login profile without IO.
// Only MFA-purpose consuming challenges are allowed; non-consuming checks deny.
// Install OTP/send-family/issuance and selected delivery histories before use.
func NewMFALoginIssuer(c MFALoginIssuerConfig) (*MFALoginIssuer, error) {
	profile, checks, err := c.Policy.Bindings()
	if err != nil || profile.Purpose != otp.PurposeMFA || checks.Enabled || c.Delivery == nil {
		return nil, ErrInvalidConfiguration
	}
	store, err := NewContributor(c.Store)
	if err != nil || store.preauth == nil {
		return nil, ErrInvalidConfiguration
	}
	store, err = newPreparedSendContributor(store, c.Delivery, preparedSendConfig{
		preparation: otp.SendPreparationConfig{Policy: c.Policy, TemplateID: c.TemplateID, TemplateVersion: c.TemplateVersion, LocaleChain: c.LocaleChain},
		provider:    c.ProviderVersion, templates: c.Templates,
		contributors: []kernel.ContributorDescriptor{{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}, c.Delivery.Descriptor()},
	})
	if err != nil {
		return nil, err
	}
	frame := append([]byte("identity-otp-mfa-login-owner-v1\x00"), store.send.configuration[:]...)
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
	policyWire, err := json.Marshal(struct {
		Profile otp.CodeProfileSpec
		Checks  otp.CheckPolicySpec
	}{profile, checks})
	if err != nil {
		clear(frame)
		return nil, ErrInvalidConfiguration
	}
	frame = append(frame, policyWire...)
	clear(policyWire)
	configuration := sha256.Sum256(frame)
	clear(frame)
	return &MFALoginIssuer{store: store, configuration: configuration}, nil
}

// Initialize registers native lockout/digest-key identity with bounded startup
// IO. Exact retry is idempotent; changed keys and uncertain commits deny. The
// pool is borrowed. This installs no schema or business credential.
func (s *MFALoginIssuer) Initialize(ctx context.Context, pool *database.Pool) error {
	if s == nil || s.store == nil || s.store.codec == nil {
		return ErrInvalidConfiguration
	}
	return initializeIssuanceKeys(ctx, pool, s.store, s.store.codec.maximumDuration, s.store.codec.codeVersions)
}

// Configuration returns immutable non-secret profile identity for the MFA
// service's original preparation binding. It is not a live admission token.
func (s *MFALoginIssuer) Configuration() ([32]byte, error) {
	if s == nil || s.store == nil || s.configuration == ([32]byte{}) {
		return [32]byte{}, ErrInvalidConfiguration
	}
	return s.configuration, nil
}

// DeliveryContributor returns the actual native encrypted-delivery owner.
func (s *MFALoginIssuer) DeliveryContributor() *deliverypg.Contributor {
	if s == nil || s.store == nil || s.store.send == nil {
		return nil
	}
	return s.store.send.delivery
}

// MFALoginSendInput is code/bearer-free original preparation. Continuation must
// retain the real consumed-primary arm and verified recipient/child correlation;
// ExpiresAt must not exceed the actual child's original lifetime. The native MFA
// service validates current primary, child, confirmed factor, recipient, policy
// and send risk before generation and protected persistence. This struct alone
// grants none of those authorities and must not be constructed from client JSON.
type MFALoginSendInput struct {
	Continuation        otp.Continuation
	Authority           AttemptAuthority
	Recipient           kernel.RecipientRecord
	IssuedAt, ExpiresAt time.Time
}

func (s *MFALoginIssuer) original(ctx context.Context, root identity.Command, input MFALoginSendInput, generation uint64) (sendRequestRecord, envelope.Context, error) {
	if s == nil || s.store == nil {
		return sendRequestRecord{}, envelope.Context{}, ErrInvalidCommand
	}
	internal := MFAEnrollmentSendInput{Continuation: input.Continuation, Authority: input.Authority, Recipient: input.Recipient, IssuedAt: input.IssuedAt, ExpiresAt: input.ExpiresAt}
	return originalMFASend(ctx, s.store, root, internal, generation, mfaLoginSendOperation(), "identity-otp-mfa-login-send-v1", s.configuration)
}

// Generate runs only after the native MFA coordinator acknowledges generation
// start. It delegates actual code/digest/rendering to OTP's existing preparer,
// retains one encrypted output and persists nothing. Never replace ambiguous
// or retained output with another generation. Cancellation returns no output.
func (s *MFALoginIssuer) Generate(ctx context.Context, root identity.Command, input MFALoginSendInput, generation uint64) ([]byte, error) {
	record, aad, err := s.original(ctx, root, input, generation)
	if err != nil {
		return nil, err
	}
	return s.store.generatePreparedSend(ctx, root, record, generation, aad)
}

// PreparedMFALoginSend holds immutable original challenge/delivery custody, not
// a successful factor proof. Copies borrow the same native owners and may only
// persist in the registered MFA owner's Work. Zero denies; no resource is owned.
type PreparedMFALoginSend struct {
	phase     *issuanceContributor
	generated identity.Command
	root      identity.FeatureCommandSpec
}

// Restore authenticates unchanged original input/profile/generation/browser and
// encrypted output without generating, renewing time or accessing a database.
func (s *MFALoginIssuer) Restore(ctx context.Context, root identity.Command, input MFALoginSendInput, generation uint64, wire []byte) (PreparedMFALoginSend, error) {
	record, aad, err := s.original(ctx, root, input, generation)
	if err != nil {
		return PreparedMFALoginSend{}, err
	}
	spec, _ := root.Feature()
	bearer, _ := root.PreAuthCookie()
	phase, generated, err := restoreSendOutputContext(ctx, s.store, s.store.send.delivery, spec.Binding, generation, bearer, wire, aad)
	if err != nil {
		return PreparedMFALoginSend{}, err
	}
	custody, _, err := s.store.authenticateIssuance(ctx, generated)
	if err != nil {
		return PreparedMFALoginSend{}, err
	}
	actual, _ := custody.challenge.Bindings()
	expected, err := encodeSendRequestRecord(record, spec.Binding)
	if err != nil {
		return PreparedMFALoginSend{}, err
	}
	defer clear(expected)
	got, err := encodeSendRequestRecord(sendRequestRecord{continuation: actual.Continuation, policy: actual.Policy, authority: custody.authority, issuedAt: actual.IssuedAt, expiresAt: actual.ExpiresAt, recipient: custody.recipient}, spec.Binding)
	defer clear(got)
	if err != nil || !reflect.DeepEqual(got, expected) {
		return PreparedMFALoginSend{}, ErrInvalidCommand
	}
	return PreparedMFALoginSend{phase: phase, generated: generated, root: spec}, nil
}

// Plan returns an owned declaration for the original encrypted delivery.
func (p PreparedMFALoginSend) Plan() (kernel.DeliveryPlan, error) {
	if p.phase == nil {
		return kernel.DeliveryPlan{}, ErrInvalidCommand
	}
	return p.phase.prepared.Plan()
}

// Persist applies real OTP/send-family effects and stages actual delivery in
// this native MFA command's sole Work. Admit the original consumed primary,
// signed child, confirmed factor, recipient, policy and protected risk first;
// repeat time/authority fences after waits. No child, primary or session is used.
func (p PreparedMFALoginSend) Persist(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, root identity.Command) error {
	if p.phase == nil || owner == nil || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) {
		return ErrInvalidCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, root); err != nil {
		return err
	}
	spec, ok := root.Feature()
	if !ok || spec.Operation != mfaLoginSendOperation() || !reflect.DeepEqual(spec, p.root) {
		return ErrInvalidCommand
	}
	_, err := p.phase.applyIssuance(ctx, w, p.generated, owner)
	return err
}

// Format redacts retained keys, configuration and original delivery custody.
func (MFALoginIssuerConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.MFALoginIssuerConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (MFALoginIssuerConfig) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText rejects implicit configuration export.
func (MFALoginIssuerConfig) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// Format redacts original input.
func (MFALoginSendInput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.MFALoginSendInput(redacted)"))
}

// MarshalJSON rejects original-input export.
func (MFALoginSendInput) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText rejects original-input export.
func (MFALoginSendInput) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// Format redacts native owner identity.
func (MFALoginIssuer) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.MFALoginIssuer(redacted)"))
}

// MarshalJSON rejects issuer export.
func (MFALoginIssuer) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText rejects issuer export.
func (MFALoginIssuer) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// Format redacts original prepared delivery.
func (PreparedMFALoginSend) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PreparedMFALoginSend(redacted)"))
}

// MarshalJSON rejects prepared-delivery export.
func (PreparedMFALoginSend) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText rejects prepared-delivery export.
func (PreparedMFALoginSend) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
