package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	secretenvelope "github.com/faustbrian/go-secret-envelope"
)

// ProviderProfile pins a retained deployment provider and delivery-policy
// revision. It contains no credentials, transport or provider callback. Zero is
// invalid: Provider is 1..128 printable ASCII bytes, PolicyVersion is positive.
type ProviderProfile struct {
	Provider      string
	PolicyVersion uint64
}

// ContributorConfig configures pre-transaction encrypted admission, not a Queue
// or recipient authorization policy. All fields are required. Deployment and
// ActiveEnvelopeKeyID are 1..128 printable ASCII bytes. Timeout is 1..30 seconds.
// Key/profile maps contain 1..32 positive versions; every key is nonzero and the
// current version must be retained. Keys must remain available while referenced.
// Maps are copied; callers must not mutate them during construction.
type ContributorConfig struct {
	Deployment              string
	CurrentDigestKeyVersion uint32
	RetainedDigestKeys      map[uint32][32]byte
	ActiveEnvelopeKeyID     string
	PreparationTimeout      time.Duration
	ProviderProfiles        map[uint64]ProviderProfile
}

// IntentInput is sensitive invocation-memory input supplied by an owned workflow
// after current authorization, recipient discovery and versioned rendering.
// It does not authenticate a caller or authorize a recipient. EffectIndex is
// original-command class position (zero is valid); batches strictly increase it.
// Template/provider versions are positive retained versions. ExpiresAt is an
// exclusive post-epoch microsecond-exact UTC instant, never renewed here.
// NoOpEquivalent uses the same public declaration shape but persists no sendable
// custody. Core Recipient and RenderedMessage bounds are enforced before crypto.
type IntentInput struct {
	EffectIndex                    uint16
	Purpose, SubjectID, TemplateID string
	TemplateVersion                uint32
	ProviderConfigVersion          uint64
	ExpiresAt                      time.Time
	Recipient                      delivery.Recipient
	Rendered                       delivery.RenderedMessage
	NoOpEquivalent                 bool
}

// Contributor is the owned optional encrypted-effect persistence participant.
// Enlist this exact pointer last in the original coordinator declaration. It
// owns no pool, transaction, coordinator, registry, provider transport or worker.
// Immutable configuration is safe for concurrent preparations and independent
// Work invocations; each Work is serial-use. Zero is invalid.
type Contributor struct {
	store       *intentStore
	current     uint32
	envelopeKey string
}

var _ identitypostgres.DeliveryContributor = (*Contributor)(nil)

// NewContributor snapshots the retained profiles/keys without IO. It borrows the
// secret-envelope service, which must support concurrent bounded calls and
// prompt entropy/key-provider cancellation. The caller owns its lifetime. It
// must install MigrationSource and the owned outbox schema before persistence.
// This constructor does not enable standalone Queue methods or grant workflow
// authority; application consumers do not implement missing domain stores.
func NewContributor(config ContributorConfig, service *secretenvelope.Service) (*Contributor, error) {
	if config.CurrentDigestKeyVersion == 0 || config.RetainedDigestKeys[config.CurrentDigestKeyVersion] == ([32]byte{}) || !safeID(config.ActiveEnvelopeKeyID, false) {
		return nil, delivery.ErrInvalidInput
	}
	codec, err := newPayloadCodec(service, config.RetainedDigestKeys, config.PreparationTimeout)
	if err != nil {
		return nil, err
	}
	if len(config.ProviderProfiles) < 1 || len(config.ProviderProfiles) > 32 {
		return nil, delivery.ErrInvalidInput
	}
	profiles := make(map[uint64]providerProfile, len(config.ProviderProfiles))
	for version, p := range config.ProviderProfiles {
		profiles[version] = providerProfile{name: p.Provider, policyVersion: p.PolicyVersion}
	}
	store, err := newIntentStore(config.Deployment, codec, profiles)
	if err != nil {
		return nil, err
	}
	return &Contributor{store: store, current: config.CurrentDigestKeyVersion, envelopeKey: config.ActiveEnvelopeKeyID}, nil
}

// Descriptor returns the stable versioned public composition identity without
// IO. Descriptor equality grants no execution or recovery authority.
func (*Contributor) Descriptor() identitypostgres.ContributorDescriptor {
	return (*intentStore)(nil).Descriptor()
}

// ValidateDeliveryPlan performs bounded pure declaration validation only. The
// coordinator authenticates execution against this exact enlisted instance;
// caller-supplied safe metadata is never a workflow authorization proof.
func (c *Contributor) ValidateDeliveryPlan(b identity.CommandBinding, p identitypostgres.DeliveryPlan) error {
	if c == nil || c.store == nil {
		return delivery.ErrInvalidInput
	}
	return c.store.ValidateDeliveryPlan(b, p)
}

type preparedDelivery struct {
	owner      *Contributor
	binding    identity.CommandBinding
	plan       identitypostgres.DeliveryPlan
	envelopes  []identitypostgres.DeliveryEnvelope
	recipients []recipientFence
}

// PreparedDelivery is immutable encrypted invocation custody, not an enqueue
// receipt, authorization proof or provider result. Only Contributor.Prepare
// constructs it; zero is invalid. Copies may be read concurrently and used on
// independent original Work values. It contains no transaction handle. It must
// never be serialized, logged as fields or retained beyond workflow lifetime.
type PreparedDelivery struct{ state *preparedDelivery }

// Plan returns an owned safe declaration for the original CommandPlan. Mutating
// it cannot change this preparation. It contains no addresses, content or
// ciphertext; a copied plan still grants no staging or recipient authority.
func (p PreparedDelivery) Plan() (identitypostgres.DeliveryPlan, error) {
	if p.state == nil {
		return identitypostgres.DeliveryPlan{}, delivery.ErrInvalidInput
	}
	plan := p.state.plan
	plan.Intents = append([]identitypostgres.DeliveryIntentPlan(nil), plan.Intents...)
	return plan, nil
}

// Prepare validates 1..16 strictly ordered effects and freezes authenticated
// recipient/rendering custody before the original transaction opens. Every
// shape is checked before any key-provider operation. Plaintext encoding and
// resulting aggregate custody are bounded to 1MiB; each envelope is at most
// 524288 bytes. The earlier caller, preparation timeout or individual expiry
// wins. Failure returns no usable prefix and never issues or renews a credential.
// It does not discover/authorize recipients or infer authority from binding IDs.
func (c *Contributor) Prepare(ctx context.Context, b identity.CommandBinding, inputs []IntentInput) (PreparedDelivery, error) {
	if c == nil {
		return PreparedDelivery{}, delivery.ErrInvalidInput
	}
	return c.prepareVersion(ctx, b, inputs, c.current)
}

// prepareVersion is owned keyed replay selection, not caller-selected crypto
// policy. Keep the enlisted pointer as custody owner while using the allocation's
// original retained fingerprint key. The active envelope key may rotate freely.
func (c *Contributor) prepareVersion(ctx context.Context, b identity.CommandBinding, inputs []IntentInput, version uint32) (PreparedDelivery, error) {
	if c == nil || c.store == nil || ctx == nil || len(inputs) < 1 || len(inputs) > 16 {
		return PreparedDelivery{}, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return PreparedDelivery{}, err
	}
	if c.store.codec.keys[version] == ([32]byte{}) {
		return PreparedDelivery{}, delivery.ErrUnavailable
	}
	bounded, stop := context.WithTimeout(ctx, c.store.codec.timeout)
	defer stop()
	bindings, err := c.validateInputs(b, inputs)
	if err != nil {
		return PreparedDelivery{}, err
	}
	p := &preparedDelivery{owner: c, binding: b, plan: identitypostgres.DeliveryPlan{Contributor: c.Descriptor(), Intents: make([]identitypostgres.DeliveryIntentPlan, len(inputs))}, envelopes: make([]identitypostgres.DeliveryEnvelope, len(inputs))}
	bytes := 0
	for n, input := range inputs {
		bindings[n].DigestKeyVersion = version
		bound, envelope, err := c.store.codec.seal(bounded, bindings[n], payload{Recipient: input.Recipient, Rendered: input.Rendered}, c.envelopeKey)
		if err != nil {
			return PreparedDelivery{}, err
		}
		bytes += len(envelope.Ciphertext)
		if bytes > 1<<20 {
			return PreparedDelivery{}, delivery.ErrInvalidInput
		}
		p.plan.Intents[n], p.envelopes[n] = bound.Intent, envelope
	}
	if err := bounded.Err(); err != nil {
		return PreparedDelivery{}, err
	}
	return PreparedDelivery{state: p}, nil
}

// validateInputs owns the shared pre-cryptographic shape and aggregate bounds.
// It neither reads authority nor authorizes recipient custody. Admission uses
// it before policy so callbacks cannot receive malformed or unbounded inputs.
func (c *Contributor) validateInputs(b identity.CommandBinding, inputs []IntentInput) ([]payloadBinding, error) {
	bindings, err := c.validateInputShape(b, inputs)
	if err != nil {
		return nil, err
	}
	for _, input := range inputs {
		if !input.ExpiresAt.After(time.Now()) {
			return nil, delivery.ErrExpired
		}
	}
	return bindings, nil
}

// Historical intent matching must retain the original expiry even after it has
// passed. This shape-only validator never permits fresh encryption or staging.
func (c *Contributor) validateInputShape(b identity.CommandBinding, inputs []IntentInput) ([]payloadBinding, error) {
	if c == nil || c.store == nil || len(inputs) < 1 || len(inputs) > 16 {
		return nil, delivery.ErrInvalidInput
	}
	bindings := make([]payloadBinding, len(inputs))
	bytes := 0
	for n, input := range inputs {
		if n > 0 && inputs[n-1].EffectIndex >= input.EffectIndex {
			return nil, delivery.ErrInvalidInput
		}
		message := delivery.Message{Purpose: input.Purpose, Channel: input.Rendered.Channel, Recipient: input.Recipient, TemplateID: input.TemplateID, TemplateVersion: uint64(input.TemplateVersion), LocaleChain: []string{input.Rendered.Locale}}
		if message.Validate() != nil {
			return nil, delivery.ErrInvalidInput
		}
		profile, ok := c.store.profiles[input.ProviderConfigVersion]
		if !ok {
			return nil, delivery.ErrUnavailable
		}
		bound := payloadBinding{Deployment: c.store.deployment, Command: b, Intent: identitypostgres.DeliveryIntentPlan{EffectID: "pending", EffectIndex: input.EffectIndex, Purpose: input.Purpose, SubjectID: input.SubjectID, TemplateID: input.TemplateID, TemplateVersion: input.TemplateVersion, ProviderConfigVersion: input.ProviderConfigVersion, ExpiresAt: input.ExpiresAt}, Provider: profile.name, PolicyVersion: profile.policyVersion, DigestKeyVersion: c.current, NoOpEquivalent: input.NoOpEquivalent}
		if _, err := custodyContext(bound, false); err != nil {
			return nil, err
		}
		wire, err := encodePayload(payload{Recipient: input.Recipient, Rendered: input.Rendered})
		bytes += len(wire)
		clear(wire)
		if err != nil || bytes > 1<<20 {
			return nil, delivery.ErrInvalidInput
		}
		bound.Intent.EffectID = deliveryEffectID(c.store.deployment, b, input.EffectIndex)
		bindings[n] = bound
	}
	return bindings, nil
}

// Stage copies previously prepared ciphertext into the original open Work. The
// preparation must belong to this contributor and match the full original
// binding. This performs no encryption, SQL, sender call or transaction closure.
// The original plan must declare all effects. Success is provisional; Commit
// authenticates them under its exact enlisted contributor. On any staging
// failure the owning workflow must Abort, never commit a partial prefix. Work
// must be used serially and cannot be retained by callers beyond its lifetime.
func (c *Contributor) Stage(ctx context.Context, w identitypostgres.Work, p PreparedDelivery) error {
	if c == nil || c.store == nil || ctx == nil || p.state == nil || p.state.owner != c {
		return delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := w.Scope()
	if err != nil {
		return err
	}
	if b != p.state.binding {
		return delivery.ErrForbidden
	}
	for _, intent := range p.state.plan.Intents {
		if !intent.ExpiresAt.After(time.Now()) {
			return delivery.ErrExpired
		}
	}
	for _, v := range p.state.envelopes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := w.StageDeliveryFor(c, v); err != nil {
			return err
		}
	}
	return nil
}

// PersistDelivery is invoked only by Coordinator under this exact enlisted
// participant. It authenticates local custody before SQL, uses the same Work
// for intent/outbox writes and never invokes KMS, provider IO or a new transaction.
func (c *Contributor) PersistDelivery(ctx context.Context, w identitypostgres.Work) error {
	if c == nil || c.store == nil {
		return delivery.ErrInvalidInput
	}
	return c.store.persistWork(ctx, w, c)
}

// RecoverParticipant supplies retained original-binding evidence during this
// exact participant invocation. Pruned payloads do not prove noncommit. No
// provider work, re-enqueue, receipt reconstruction or transaction closure occurs.
func (c *Contributor) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	if c == nil || c.store == nil {
		return identitypostgres.RecoveryUnknown, delivery.ErrInvalidInput
	}
	return c.store.recoverWork(ctx, w, c)
}

func admissionRedact(s fmt.State) { _, _ = s.Write([]byte("delivery.postgres(redacted)")) }

// Format redacts keys and deployment configuration for every formatting verb.
func (ContributorConfig) Format(s fmt.State, _ rune) { admissionRedact(s) }

// Format redacts recipients and rendered content for every formatting verb.
func (IntentInput) Format(s fmt.State, _ rune) { admissionRedact(s) }

// Format redacts invocation custody for every formatting verb.
func (PreparedDelivery) Format(s fmt.State, _ rune) { admissionRedact(s) }

// Format redacts borrowed-service configuration for every formatting verb.
func (Contributor) Format(s fmt.State, _ rune) { admissionRedact(s) }

// LogValue prevents structured logging from exposing keys or configuration.
func (ContributorConfig) LogValue() slog.Value {
	return slog.StringValue("delivery.postgres(redacted)")
}

// LogValue prevents structured logging from exposing recipient/content fields.
func (IntentInput) LogValue() slog.Value { return slog.StringValue("delivery.postgres(redacted)") }

// LogValue prevents structured logging from exposing invocation custody.
func (PreparedDelivery) LogValue() slog.Value { return slog.StringValue("delivery.postgres(redacted)") }

// LogValue prevents structured logging from exposing borrowed configuration.
func (Contributor) LogValue() slog.Value { return slog.StringValue("delivery.postgres(redacted)") }

// MarshalJSON denies configuration serialization rather than exporting keys.
func (ContributorConfig) MarshalJSON() ([]byte, error) {
	return nil, delivery.ErrSerializationForbidden
}

// MarshalJSON denies serialization of recipient/rendering input.
func (IntentInput) MarshalJSON() ([]byte, error) { return nil, delivery.ErrSerializationForbidden }

// MarshalJSON denies serialization of opaque invocation custody.
func (PreparedDelivery) MarshalJSON() ([]byte, error) { return nil, delivery.ErrSerializationForbidden }

// MarshalJSON denies serialization of contributor configuration and services.
func (Contributor) MarshalJSON() ([]byte, error) { return nil, delivery.ErrSerializationForbidden }

// MarshalText denies configuration serialization rather than exporting keys.
func (ContributorConfig) MarshalText() ([]byte, error) {
	return nil, delivery.ErrSerializationForbidden
}

// MarshalText denies serialization of recipient/rendering input.
func (IntentInput) MarshalText() ([]byte, error) { return nil, delivery.ErrSerializationForbidden }

// MarshalText denies serialization of opaque invocation custody.
func (PreparedDelivery) MarshalText() ([]byte, error) { return nil, delivery.ErrSerializationForbidden }

// MarshalText denies serialization of contributor configuration and services.
func (Contributor) MarshalText() ([]byte, error) { return nil, delivery.ErrSerializationForbidden }
