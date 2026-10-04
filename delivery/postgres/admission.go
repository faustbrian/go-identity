package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	auditpostgres "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	secretenvelope "github.com/faustbrian/go-secret-envelope"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
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
	// Cancellation explicitly enables authenticated original-command local
	// cancellation. Requires StateTracking and CancellationVersion migration.
	// False preserves existing enqueue plan identity and status-only composition.
	Cancellation bool
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
// authenticated local cancellation,
// not the complete Queue lifecycle. It composes participants and performs no provider
// invocation, retry, credential issuance or identity mutation. The caller owns
// the borrowed primary pool, authorization dependency and envelope service.
// Concurrent calls are supported; no goroutines/background work are started.
// Zero is invalid. Applications do not supply domain stores or orchestration.
type EnqueueService struct {
	executor      *enqueueExecutor
	repository    *identitypostgres.Repository
	renderer      *delivery.TemplateRenderer
	policies      *retainedPolicies
	keyed         *keyedAdmission
	stateTracking bool
	cancellation  *cancelExecutor
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
// CancellationVersion for their respective features. It never runs migrations.
// Pure validation precedes bounded idempotent policy/namespace registration.
// Registrations commit independently and survive a later constructor failure;
// neither is a business command or enqueue receipt. A lost acknowledgement is
// unknown; retry exact settings. No network Sender is needed for admission.
// If Coordinator.AdmissionPolicy is nil, historical observation uses authorize,
// the system clock and PolicyVersion; an explicit observation policy is retained.
func NewEnqueueService(ctx context.Context, pool *database.Pool, c EnqueueConfig, service *secretenvelope.Service, authorize authorization.Service, templates []delivery.Template) (*EnqueueService, error) {
	if ctx == nil || pool == nil || pool.Raw() == nil || c.Timeout < time.Second || c.Timeout > 5*time.Second || c.NamespaceKey == ([32]byte{}) || !safeID(c.PolicyID, false) || c.PolicyVersion == 0 || c.AuditRetentionVersion == 0 || len(c.Policies) < 1 || len(c.Policies) > 32 || c.Cancellation && !c.StateTracking {
		return nil, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
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
	w, stop := context.WithTimeout(ctx, c.Timeout)
	defer stop()
	if c.StateTracking {
		// Resolve the selected columns before any policy/namespace registration.
		// This reads no rows or ciphertext and never applies migrations silently.
		if _, err := pool.Raw().Exec(w, `SELECT status_version,local_stop_state,local_stop_at FROM identity.delivery_intents WHERE false`); err != nil {
			return nil, attemptFailure(w, err)
		}
	}
	if c.Cancellation {
		if _, err := pool.Raw().Exec(w, `SELECT binding_digest,generation,before_version,after_version,result_state,local_cancelled FROM identity.delivery_cancellations WHERE false`); err != nil {
			return nil, attemptFailure(w, err)
		}
	}
	policies, err := newRetainedPolicies(w, pool.Raw(), c.Custody.Deployment, c.Policies, c.Timeout)
	if err != nil {
		return nil, err
	}
	keyed, err := newKeyedAdmission(w, pool.Raw(), c.Custody.Deployment, c.NamespaceKey, c.Timeout)
	if err != nil {
		return nil, err
	}
	s := &EnqueueService{executor: executor, repository: repo, renderer: renderer, policies: policies, keyed: keyed, stateTracking: c.StateTracking}
	if c.Cancellation {
		store, err := newAttemptStore(pool.Raw(), c.Custody.Deployment, custody.store.codec, delivery.DefaultConfig(), c.Timeout)
		if err != nil {
			return nil, err
		}
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
	return s, nil
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
