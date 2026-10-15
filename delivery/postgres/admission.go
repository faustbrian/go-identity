package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	auditpostgres "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// EnqueueConfig fixes admission policy and retained deployment custody. Timeout
// is 1..5 seconds and bounds the entire call, including policy, rendering and
// persistence. PolicyID, positive versions, a nonzero namespace key and 1..32
// valid Policies are mandatory. Each custody provider's policy must be retained.
// Preserve keys and policies while referenced. Configuration is copied by its
// owners; callers must not mutate it during construction. It contains secrets.
type EnqueueConfig struct {
	Custody               ContributorConfig
	Coordinator           identitypostgres.CoordinatorConfig
	PolicyID              string
	PolicyVersion         uint64
	AuditRetentionVersion uint64
	Timeout               time.Duration
	NamespaceKey          [32]byte
	Policies              map[uint64]delivery.Config
	// StateTracking explicitly selects the StateVersion migration profile for
	// no-op local-stop status. False retains the legacy admission/status schema.
	// True fails closed if the forward migration is absent; it does not enable
	// public cancellation, provider callbacks or full Queue composition.
	StateTracking bool
	// ReceiptTracking reads installed ReceiptVersion metadata without enabling
	// callbacks or retaining their credentials. Requires StateTracking. Receipts
	// implies this selection; false with nil Receipts preserves legacy queries.
	ReceiptTracking bool
	// Cancellation explicitly enables authenticated original-command local
	// cancellation. Requires StateTracking and CancellationVersion migration.
	// False preserves existing enqueue plan identity and status-only composition.
	Cancellation bool
	// Receipts explicitly enables owned signed-callback authentication and
	// protected receipt commands. Nil preserves legacy admission plan identity.
	// Requires StateTracking, ReceiptVersion and ReceiptCommandVersion migrations.
	Receipts *ReceiptAuthenticationConfig
	// Reconciliation opts into original-key provider lookup, owned encrypted
	// cursor custody and protected query commands. Requires StateTracking and
	// Receipt/Reconciliation/ReconciliationCommand/ReconciliationQuery migrations.
	Reconciliation *ReconciliationConfig
}

// EnqueueCommandRequest is trusted platform/workflow input, not HTTP JSON or
// authentication evidence. Binding and ActorScope must come from authenticated
// composition; IDs alone grant no authority. RecordID must be empty. Recipient
// must be omitted: the owned directory selects IdentifierID before rendering.
// ProviderConfigVersion is a positive retained version, preserved on every
// retry along with message, original expiry, correlation and idempotency key.
// Message slices must not be mutated during the call. NoOpEquivalent requires
// IdentifierID empty and is only for trusted enumeration-safe workflows; it
// returns the same queued result shape but persists no sendable custody.
type EnqueueCommandRequest struct {
	Binding               identity.CommandBinding
	ActorScope            authorization.DecisionContext
	IdentifierID          identity.IdentifierID
	ProviderConfigVersion uint64
	Message               delivery.Message
	IdempotencyKey        string
	ExpiresAt             time.Time
	NoOpEquivalent        bool
}

// EnqueueService owns usable durable admission, authorized status and opt-in
// authenticated local cancellation, signed provider receipts and reconciliation.
// NewQueue composes these owners with its retained worker profile. Admission
// performs no provider invocation, retry, credential issuance or identity
// mutation. The caller owns
// the borrowed primary pool, authorization dependency and envelope service.
// Concurrent calls are supported; no goroutines/background work are started.
// Zero is invalid. Applications do not supply domain stores or orchestration.
type EnqueueService struct {
	startup         *enqueueStartup
	executor        *enqueueExecutor
	repository      *identitypostgres.Repository
	renderer        *delivery.TemplateRenderer
	policies        *retainedPolicies
	keyed           *keyedAdmission
	stateTracking   bool
	receiptTracking bool
	cancellation    *cancelExecutor
	receipts        *receiptExecutor
	reconciliation  *reconciliationExecutor
}

func (EnqueueConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("delivery.postgres.EnqueueConfig(redacted)"))
}
func (EnqueueConfig) LogValue() slog.Value {
	return slog.StringValue("delivery.postgres.EnqueueConfig(redacted)")
}

// MarshalJSON rejects secret configuration serialization.
func (EnqueueConfig) MarshalJSON() ([]byte, error) { return nil, delivery.ErrSerializationForbidden }
func (EnqueueCommandRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("delivery.postgres.EnqueueCommandRequest(redacted)"))
}
func (EnqueueCommandRequest) LogValue() slog.Value {
	return slog.StringValue("delivery.postgres.EnqueueCommandRequest(redacted)")
}

// MarshalJSON rejects implicit sensitive workflow serialization.
func (EnqueueCommandRequest) MarshalJSON() ([]byte, error) {
	return nil, delivery.ErrSerializationForbidden
}
func (EnqueueService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("delivery.postgres.EnqueueService(redacted)"))
}
func (EnqueueService) LogValue() slog.Value {
	return slog.StringValue("delivery.postgres.EnqueueService(redacted)")
}

// MarshalJSON rejects runtime dependency and secret serialization.
func (EnqueueService) MarshalJSON() ([]byte, error) { return nil, delivery.ErrSerializationForbidden }

// NewEnqueueService constructs owned repository, renderer, native command,
// protected audit, lifecycle, ciphertext and sole kernel-coordinator composition
// from one borrowed primary pool. Install the public kernel/audit/outbox and
// delivery migrations through KeyedVersion first; select StateVersion and
// CancellationVersion for their respective features. Receipts also requires
// ReceiptVersion and ReceiptCommandVersion. It never runs migrations.
// Pure validation precedes bounded idempotent policy/namespace registration.
// Registrations commit independently and survive a later constructor failure;
// neither is a business command or enqueue receipt. A lost acknowledgement is
// unknown; retry exact settings. No network Sender is needed for admission.
// If Coordinator.AdmissionPolicy is nil, historical observation uses authorize,
// the system clock and PolicyVersion; an explicit observation policy is retained.
func NewEnqueueService(ctx context.Context, pool *database.Pool, c EnqueueConfig, service *secretenvelope.Service, authorize authorization.Service, templates []delivery.Template) (*EnqueueService, error) {
	if ctx == nil || !validEnqueueConfigShape(pool, c) {
		return nil, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s, err := NewUninitializedEnqueueService(pool, c, service, authorize, templates)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.Initialize(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// NewUninitializedEnqueueService constructs the same real owned delivery graph
// as NewEnqueueService without IO, entropy, migrations or callbacks. It copies
// configuration; callers must not mutate inputs during construction. Borrowed
// pool, envelope and authorization owners remain caller-owned. NewWorker and
// NewQueue may be composed before startup, but every operation fails closed
// until Initialize succeeds. Install the selected migrations explicitly first.
// It starts no goroutines and creates no alternate queue or command authority.
func NewUninitializedEnqueueService(pool *database.Pool, c EnqueueConfig, service *secretenvelope.Service, authorize authorization.Service, templates []delivery.Template) (*EnqueueService, error) {
	if !validEnqueueConfigShape(pool, c) {
		return nil, delivery.ErrInvalidInput
	}
	if len(c.Coordinator.RetainedFingerprintKeys) < 1 || len(c.Coordinator.RetainedFingerprintKeys) > 32 {
		return nil, delivery.ErrInvalidInput
	}
	// Reconciliation builds later coordinators from this retained profile, so
	// its future construction must not observe caller map or pointer mutation.
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	if p := c.Coordinator.QueryPolicy; p != nil {
		copy := *p
		c.Coordinator.QueryPolicy = &copy
	}
	if p := c.Coordinator.AdmissionPolicy; p != nil {
		copy := *p
		c.Coordinator.AdmissionPolicy = &copy
	}
	if p := c.Coordinator.FinalAuthentication; p != nil {
		copy := *p
		c.Coordinator.FinalAuthentication = &copy
	}
	for version, policy := range c.Policies {
		if version == 0 || policy.Validate() != nil {
			return nil, delivery.ErrInvalidInput
		}
	}
	for _, profile := range c.Custody.ProviderProfiles {
		if _, ok := c.Policies[profile.PolicyVersion]; !ok {
			return nil, delivery.ErrInvalidInput
		}
	}
	receiptAuth, receiptClock, err := receiptConfiguration(c)
	if err != nil {
		return nil, err
	}
	reconcile, err := reconciliationConfiguration(c)
	if err != nil {
		return nil, err
	}
	custody, err := NewContributor(c.Custody, service)
	if err != nil {
		return nil, err
	}
	renderer, err := delivery.NewTemplateRenderer(templates)
	if err != nil {
		return nil, err
	}
	repo, err := identitypostgres.NewRepository(pool, identitypostgres.Config{MaximumDuration: c.Timeout})
	if err != nil {
		return nil, admissionError(err)
	}
	native, err := NewEnqueueContributor(custody)
	if err != nil {
		return nil, err
	}
	audits, err := auditpostgres.NewIdentityContributor(auditpostgres.Config{})
	if err != nil {
		return nil, admissionError(err)
	}
	lifecycle, err := identityoutbox.NewContributor()
	if err != nil {
		return nil, admissionError(err)
	}
	registry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{repo, native, audits, lifecycle, custody})
	if err != nil {
		return nil, admissionError(err)
	}
	// Historical observation is required for expired exact-request recovery.
	// Use the same current authorization service unless explicitly configured;
	// this grants no policy bypass or replay execution authority.
	if c.Coordinator.AdmissionPolicy == nil {
		c.Coordinator.AdmissionPolicy = &identitypostgres.CommandQueryPolicy{Authorization: authorize, Clock: clock.System{}, PolicyVersion: c.PolicyVersion}
	}
	coordinator, err := identitypostgres.NewCoordinator(pool, registry, c.Coordinator)
	if err != nil {
		return nil, admissionError(err)
	}
	executor, err := newEnqueueExecutor(coordinator, registry, native, custody, authorize, c.PolicyID, c.PolicyVersion, c.AuditRetentionVersion, c.Timeout)
	if err != nil {
		return nil, err
	}
	policies, err := prepareRetainedPolicies(pool.Raw(), c.Custody.Deployment, c.Policies, c.Timeout)
	if err != nil {
		return nil, err
	}
	keyed, err := prepareKeyedAdmission(pool.Raw(), c.Custody.Deployment, c.NamespaceKey, c.Timeout)
	if err != nil {
		return nil, err
	}
	s := &EnqueueService{startup: &enqueueStartup{receiptTracking: c.ReceiptTracking}, executor: executor, repository: repo, renderer: renderer, policies: policies, keyed: keyed, stateTracking: c.StateTracking, receiptTracking: c.ReceiptTracking || receiptAuth != nil || reconcile != nil}
	if c.Cancellation {
		store, err := newAttemptStore(pool.Raw(), c.Custody.Deployment, custody.store.codec, delivery.DefaultConfig(), c.Timeout)
		if err != nil {
			return nil, err
		}
		store.receiptTracking = s.receiptTracking
		nativeCancel := &cancelContributor{store: store, policies: policies}
		// Both handles use the sole kernel command authority. Separate operation
		// registries keep installed enqueue plan fingerprints byte-identical when
		// cancellation is enabled; there is no second journal or transaction owner.
		cancelRegistry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{repo, nativeCancel, audits, lifecycle})
		if err != nil {
			return nil, admissionError(err)
		}
		cancelCoordinator, err := identitypostgres.NewCoordinator(pool, cancelRegistry, c.Coordinator)
		if err != nil {
			return nil, admissionError(err)
		}
		s.cancellation = &cancelExecutor{cancelCoordinator, cancelRegistry, nativeCancel}
	}
	if receiptAuth != nil {
		nativeReceipt := &receiptContributor{store: &receiptStore{deployment: c.Custody.Deployment, namespaceKey: c.NamespaceKey}}
		receiptRegistry, err := identitypostgres.NewContributorRegistry([]identitypostgres.Contributor{repo, nativeReceipt, audits, lifecycle})
		if err != nil {
			return nil, admissionError(err)
		}
		receiptCoordinator, err := identitypostgres.NewCoordinator(pool, receiptRegistry, c.Coordinator)
		if err != nil {
			return nil, admissionError(err)
		}
		s.receipts = &receiptExecutor{coordinator: receiptCoordinator, registry: receiptRegistry, native: nativeReceipt, auth: receiptAuth, clock: receiptClock}
	}
	if reconcile != nil {
		reconcile.native = &reconciliationContributor{store: &receiptStore{deployment: c.Custody.Deployment, namespaceKey: c.NamespaceKey}}
		reconcile.codec, reconcile.current, reconcile.envelopeKey = custody.store.codec, custody.current, custody.envelopeKey
		reconcile.config, reconcile.pool = c.Coordinator, pool
		if reconcile.config.QueryPolicy == nil {
			reconcile.config.QueryPolicy = &identitypostgres.CommandQueryPolicy{Authorization: authorize, Clock: clock.System{}, PolicyVersion: c.PolicyVersion}
		}
		reconcile.contributors = []identitypostgres.Contributor{repo, audits, lifecycle}
		reconcile.coordinator, _, _, err = reconcile.build(nil)
		if err != nil {
			return nil, admissionError(err)
		}
		s.reconciliation = reconcile
	}
	return s, nil
}

func validEnqueueConfigShape(pool *database.Pool, c EnqueueConfig) bool {
	return pool != nil && pool.Raw() != nil && c.Timeout >= time.Second && c.Timeout <= 5*time.Second && c.NamespaceKey != ([32]byte{}) && safeID(c.PolicyID, false) && c.PolicyVersion != 0 && c.AuditRetentionVersion != 0 && len(c.Policies) >= 1 && len(c.Policies) <= 32 && (!(c.Cancellation || c.ReceiptTracking) || c.StateTracking)
}

// Enqueue authorizes exact scope before primary recipient discovery and owned
// versioned rendering, then rechecks policy before the original coordinator
// reserves/commits. Queued means durable admission only, never provider delivery.
// Matching scoped keys retain the original intent across candidate command IDs.
// Changed input conflicts. Unknown/in-progress never authorize another key or
// command; retry this exact request/key. AdmissionUnknownError contains only an
// actually known original command; allocation uncertainty returns the redacted
// ErrOutcomeUnknown without inventing an original identity. No-op information is
// internal workflow metadata and must not be exposed as an existence bit.
// After expiry, exact matching retries may observe historical command outcomes
// under current policy but cannot allocate, encrypt, reserve or renew a send.
func (s *EnqueueService) Enqueue(ctx context.Context, r EnqueueCommandRequest) (delivery.EnqueueResult, error) {
	out := delivery.EnqueueResult{State: delivery.CommitNotCommitted, NoOpEquivalent: r.NoOpEquivalent}
	if err := s.startupCheck(ctx); err != nil {
		return out, err
	}
	if ctx == nil || s == nil || s.executor == nil || r.Binding.RecordID != "" || r.Message.Recipient != (delivery.Recipient{}) || len(r.IdempotencyKey) < 16 || !safeID(r.IdempotencyKey, false) || r.ProviderConfigVersion == 0 || r.Message.TemplateVersion > 4294967295 || r.ExpiresAt.IsZero() || r.ExpiresAt.Year() > 9999 || r.ExpiresAt.Nanosecond()%1000 != 0 {
		return out, delivery.ErrInvalidInput
	}
	w, stop := context.WithTimeout(ctx, s.executor.timeout)
	defer stop()
	if err := w.Err(); err != nil {
		return out, err
	}
	checked := r.Binding
	checked.RecordID = "enqueue-validation"
	if checked.ValidateFor(EnqueueOperation()) != nil {
		return out, delivery.ErrInvalidInput
	}
	message := r.Message
	// Validate the bounded non-recipient message before cloning or primary IO;
	// the temporary recipient is never persisted or used to select an identity.
	message.Recipient = delivery.Recipient{Channel: message.Channel, Address: "shape", ScopeDigest: strings.Repeat("0", 64)}
	if message.Validate() != nil || r.NoOpEquivalent && r.IdentifierID != "" {
		return out, delivery.ErrInvalidInput
	}
	if !r.NoOpEquivalent {
		if _, err := identity.ParseIdentifierID(string(r.IdentifierID)); err != nil {
			return out, delivery.ErrInvalidInput
		}
	}
	for _, attrs := range []authorization.Attributes{r.ActorScope.Request.Subject.Attributes, r.ActorScope.Request.Resource.Attributes, r.ActorScope.Request.Environment.Attributes, r.ActorScope.Request.Attributes} {
		if len(attrs) > 128 {
			return out, delivery.ErrInvalidInput
		}
		for name := range attrs {
			if len(name) > 128 || strings.HasPrefix(string(name), "delivery.") {
				return out, delivery.ErrInvalidInput
			}
		}
	}
	if err := s.executor.allow(w, checked, r.ActorScope); err != nil {
		return out, err
	}
	message.LocaleChain = slices.Clone(message.LocaleChain)
	message.Variables = slices.Clone(message.Variables)
	var fences []recipientFence
	if r.NoOpEquivalent {
		message.Recipient.Address = "noop@invalid"
		if message.Channel == delivery.ChannelSMS {
			message.Recipient.Address = "+10000000000"
		}
		digest := custodyMAC(s.keyed.key, "identity-delivery-noop-recipient-v1", keyedFields(s.keyed.deployment, string(r.Binding.TenantID), string(r.Binding.UserID), message.Purpose, strconv.Itoa(int(message.Channel))), nil)
		message.Recipient.ScopeDigest = hex.EncodeToString(digest[:])
	} else {
		recipient, fence, err := lookupRecipient(w, r.Binding, r.IdentifierID, message.Purpose, s.keyed, s.repository)
		if err != nil {
			return out, err
		}
		if recipient.Channel != message.Channel {
			return out, delivery.ErrForbidden
		}
		message.Recipient = recipient
		fences = []recipientFence{fence}
	}
	rendered, err := s.renderer.Render(w, message)
	if err != nil {
		return out, err
	}
	input := IntentInput{Purpose: message.Purpose, SubjectID: string(r.Binding.UserID), TemplateID: message.TemplateID, TemplateVersion: uint32(message.TemplateVersion), ProviderConfigVersion: r.ProviderConfigVersion, ExpiresAt: r.ExpiresAt, Recipient: message.Recipient, Rendered: rendered, NoOpEquivalent: r.NoOpEquivalent}
	result, err := s.executor.admit(w, r.Binding, r.ActorScope, []IntentInput{input}, s.policies, s.keyed, r.IdempotencyKey, fences)
	if result.Binding.CommandID != "" {
		out.IntentID = delivery.IntentID(result.Binding.RecordID)
	}
	switch result.Outcome {
	case identity.CommitOutcomeCommitted:
		if err == nil && result.Feature != nil && result.Feature.Operation == EnqueueOperation() && out.IntentID != "" {
			out.State = delivery.CommitCommitted
			out.Queued = true
			return out, nil
		}
		out.State = delivery.CommitUnknown
	case identity.CommitOutcomeUnknown:
		out.State = delivery.CommitUnknown
	case identity.CommitOutcomeInProgress:
		out.State = delivery.CommitInProgress
	case identity.CommitOutcomeConflict:
		out.State = delivery.CommitConflict
	}
	if out.State == delivery.CommitUnknown || out.State == delivery.CommitInProgress || errors.Is(err, delivery.ErrOutcomeUnknown) {
		if out.State == delivery.CommitNotCommitted {
			out.State = delivery.CommitUnknown
		}
		if result.Binding.CommandID != "" {
			return out, delivery.AdmissionUnknownError{CommandID: result.Binding.CommandID, IntentID: out.IntentID}
		}
		return out, delivery.ErrOutcomeUnknown
	}
	if err == nil {
		return out, delivery.ErrUnavailable
	}
	err = admissionError(err)
	if errors.Is(err, delivery.ErrConflict) {
		out.State = delivery.CommitConflict
	}
	return out, err
}

func admissionError(err error) error {
	var invalid identity.InvalidInputError
	var conflict identity.ConflictError
	var forbidden identity.ForbiddenError
	var unavailable identity.UnavailableError
	switch {
	case errors.As(err, &invalid):
		return delivery.ErrInvalidInput
	case errors.As(err, &conflict):
		return delivery.ErrConflict
	case errors.As(err, &forbidden):
		return delivery.ErrForbidden
	case errors.As(err, &unavailable):
		return delivery.ErrUnavailable
	default:
		return err
	}
}
