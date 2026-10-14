package postgres

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// ReconciliationProvider explicitly pins an original provider lookup to one
// tenant, retained custody profile and authenticated service-account actor.
// The borrowed Querier authenticates responses, must cooperate with deadlines,
// support concurrent calls, and must never send/cancel/resubmit a message.
type ReconciliationProvider struct {
	TenantID              delivery.TenantID
	ProviderConfigVersion uint64
	ActorID               identity.ActorID
	Querier               delivery.OutcomeQuerier
}

// ReconciliationConfig opts into owned public query orchestration. Timeout is
// 1s..EnqueueConfig.Timeout and Concurrency1..64 per configured provider. Providers
// contains1..32 distinct tenant/version pairs. Configuration is copied; callbacks
// are borrowed. Nil disables the feature without requiring its migrations.
type ReconciliationConfig struct {
	Timeout     time.Duration
	Concurrency uint8
	Providers   []ReconciliationProvider
}

// ReconcileCommandRequest is trusted authenticated input, not transport JSON.
// Freeze Binding, generation, status version, step and opaque Checkpoint before
// first call; replay preserves them. Empty checkpoint begins/exhausts a sequence
// but cannot reset its durable step. Only the configured service actor may query.
// No raw provider cursor, recipient or rendered body is supplied by callers.
type ReconcileCommandRequest struct {
	Binding               identity.CommandBinding
	ActorScope            authorization.DecisionContext
	ExpectedStatusVersion uint64
	ExpectedStep          uint64
	Generation            uint32
	Checkpoint            string
}

func (ReconciliationProvider) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("delivery.postgres.reconciliation(redacted)"))
}
func (ReconciliationProvider) LogValue() slog.Value {
	return slog.StringValue("delivery.postgres.reconciliation(redacted)")
}
func (ReconciliationProvider) MarshalJSON() ([]byte, error) {
	return nil, delivery.ErrSerializationForbidden
}
func (ReconciliationConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("delivery.postgres.reconciliation(redacted)"))
}
func (ReconciliationConfig) LogValue() slog.Value {
	return slog.StringValue("delivery.postgres.reconciliation(redacted)")
}
func (ReconciliationConfig) MarshalJSON() ([]byte, error) {
	return nil, delivery.ErrSerializationForbidden
}
func (ReconcileCommandRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("delivery.postgres.reconciliation(redacted)"))
}
func (ReconcileCommandRequest) LogValue() slog.Value {
	return slog.StringValue("delivery.postgres.reconciliation(redacted)")
}
func (ReconcileCommandRequest) MarshalJSON() ([]byte, error) {
	return nil, delivery.ErrSerializationForbidden
}
func (ReconcileCommandRequest) MarshalText() ([]byte, error) {
	return nil, delivery.ErrSerializationForbidden
}

type reconciliationProviderKey struct {
	tenant  string
	version uint64
}
type reconciliationLookup struct {
	actor identity.ActorID
	query *delivery.OutcomeQueryExecutor
}
type reconciliationExecutor struct {
	providers    map[reconciliationProviderKey]reconciliationLookup
	config       identitypostgres.CoordinatorConfig
	contributors []identitypostgres.Contributor
	native       *reconciliationContributor
	codec        *payloadCodec
	current      uint32
	envelopeKey  string
	coordinator  *identitypostgres.Coordinator
	pool         *database.Pool
}

func reconciliationConfiguration(c EnqueueConfig) (*reconciliationExecutor, error) {
	if c.Reconciliation == nil {
		return nil, nil
	}
	cfg := c.Reconciliation
	if !c.StateTracking || cfg.Timeout < time.Second || cfg.Timeout > c.Timeout || cfg.Concurrency < 1 || cfg.Concurrency > 64 || len(cfg.Providers) < 1 || len(cfg.Providers) > 32 {
		return nil, delivery.ErrInvalidInput
	}
	e := &reconciliationExecutor{providers: make(map[reconciliationProviderKey]reconciliationLookup, len(cfg.Providers))}
	for _, p := range cfg.Providers {
		if !safeID(string(p.TenantID), false) || !safeID(string(p.ActorID), false) || p.ProviderConfigVersion == 0 {
			return nil, delivery.ErrInvalidInput
		}
		if _, ok := c.Custody.ProviderProfiles[p.ProviderConfigVersion]; !ok {
			return nil, delivery.ErrInvalidInput
		}
		key := reconciliationProviderKey{string(p.TenantID), p.ProviderConfigVersion}
		if _, ok := e.providers[key]; ok {
			return nil, delivery.ErrInvalidInput
		}
		query, err := delivery.NewOutcomeQueryExecutor(cfg.Timeout, cfg.Concurrency, p.Querier)
		if err != nil {
			return nil, err
		}
		e.providers[key] = reconciliationLookup{p.ActorID, query}
	}
	return e, nil
}
func (e *reconciliationExecutor) build(p *reconciliationPrepared) (*identitypostgres.Coordinator, *identitypostgres.ContributorRegistry, *reconciliationQueryContributor, error) {
	native := &reconciliationQueryContributor{native: e.native, codec: e.codec, prepared: p}
	members := make([]identitypostgres.Contributor, 0, len(e.contributors)+1)
	members = append(members, e.contributors...)
	members = append(members, native)
	registry, err := identitypostgres.NewContributorRegistry(members)
	if err != nil {
		return nil, nil, nil, err
	}
	coordinator, err := identitypostgres.NewCoordinator(e.pool, registry, e.config)
	return coordinator, registry, native, err
}

// Reconcile performs one bounded read-only original-key provider query outside
// SQL transactions, row locks and command reservations, then atomically commits
// scoped evidence/progress/custody/status/audit/lifecycle/original result through
// the sole identity coordinator. Requires Reconciliation and QueryVersion.
// Exact historical replay reauthorizes and returns its original result without
// querying. Pending/unknown commands never query again or acquire replacements.
// TransientFailure is unsupported query settlement: ErrUnavailable records no
// progress and never silently drops RetryAfter or grants resend permission.
// Original payload expiry does not prevent lookup. Times normalize to UTC
// microseconds; raw cursors are recoverably encrypted and erased on settlement.
func (s *EnqueueService) Reconcile(ctx context.Context, r ReconcileCommandRequest) (delivery.ReconcileResult, error) {
	if err := s.startupCheck(ctx); err != nil {
		return delivery.ReconcileResult{}, err
	}
	if ctx == nil || s == nil || s.executor == nil || s.keyed == nil || s.keyed.pool == nil || s.reconciliation == nil || r.Binding.ValidateFor(ReconcileOperation()) != nil || r.ExpectedStatusVersion == 0 || r.ExpectedStatusVersion == math.MaxUint64 || r.ExpectedStep >= math.MaxInt64-1 || r.Generation == 0 || len(r.Checkpoint) > 43 {
		return delivery.ReconcileResult{}, delivery.ErrInvalidInput
	}
	if r.Checkpoint != "" {
		raw, err := base64.RawURLEncoding.DecodeString(r.Checkpoint)
		if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != r.Checkpoint {
			return delivery.ReconcileResult{}, delivery.ErrInvalidInput
		}
	}
	work, stop := context.WithTimeout(ctx, s.executor.timeout)
	defer stop()
	caller, err := cancellationScope(r.ActorScope, delivery.IntentID(r.Binding.RecordID))
	if err != nil {
		return delivery.ReconcileResult{}, err
	}
	caller.Request.Resource.Attributes["delivery.generation"] = authorization.IntValue(int64(r.Generation))
	if err := s.executor.allow(work, r.Binding, caller); err != nil {
		return delivery.ReconcileResult{}, err
	}
	var provider, profile string
	var noop bool
	var bindingAAD []byte
	err = s.keyed.pool.QueryRow(work, `SELECT provider,provider_version::text,no_op,binding_aad FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND subject_id=$4`, s.keyed.deployment, string(r.Binding.TenantID), r.Binding.RecordID, string(r.Binding.UserID)).Scan(&provider, &profile, &noop, &bindingAAD)
	if errors.Is(err, pgx.ErrNoRows) {
		return delivery.ReconcileResult{}, delivery.ErrNotFound
	}
	if err != nil {
		return delivery.ReconcileResult{}, attemptFailure(work, err)
	}
	if _, err := decodeUserBinding(bindingAAD, s.keyed.deployment, string(r.Binding.TenantID), r.Binding.RecordID, string(r.Binding.UserID)); err != nil {
		return delivery.ReconcileResult{}, err
	}
	version, err := strconv.ParseUint(profile, 10, 64)
	if err != nil || noop {
		return delivery.ReconcileResult{}, delivery.ErrForbidden
	}
	e := s.reconciliation
	lookup, ok := e.providers[reconciliationProviderKey{string(r.Binding.TenantID), version}]
	if !ok || lookup.actor != r.Binding.ActorID || r.Binding.ActorKind != authorization.SubjectServiceAccount {
		return delivery.ReconcileResult{}, delivery.ErrForbidden
	}
	caller.Request.Resource.Attributes["delivery.provider"] = authorization.StringValue(provider)
	caller.Request.Resource.Attributes["delivery.provider_config_version"] = authorization.StringValue(profile)
	if err := s.executor.allow(work, r.Binding, caller); err != nil {
		return delivery.ReconcileResult{}, err
	}
	request := reconciliationRequestDigest(s.keyed, r, version)
	query := identity.RecoveryQuery{CommandID: r.Binding.CommandID, TenantID: r.Binding.TenantID, UserID: r.Binding.UserID, ActorID: r.Binding.ActorID, ActorKind: r.Binding.ActorKind, OperationID: r.Binding.OperationID, RecordID: r.Binding.RecordID, LinkMode: r.Binding.LinkMode}
	observed, err := e.coordinator.ObserveCommandAdmission(work, query, caller)
	if err != nil {
		return delivery.ReconcileResult{}, admissionError(err)
	}
	if !observed.Absent {
		switch observed.Record.Outcome {
		case identity.CommitOutcomeCommitted:
			result, err := s.reconciliationResult(work, r, version, request)
			if err != nil {
				return delivery.ReconcileResult{}, err
			}
			if err := s.executor.allow(work, r.Binding, caller); err != nil {
				return delivery.ReconcileResult{}, err
			}
			return result, nil
		case identity.CommitOutcomeInProgress, identity.CommitOutcomeUnknown:
			return delivery.ReconcileResult{}, delivery.ErrOutcomeUnknown
		case identity.CommitOutcomeConflict:
			return delivery.ReconcileResult{}, delivery.ErrConflict
		default:
			return delivery.ReconcileResult{}, delivery.ErrUnavailable
		}
	}
	scope, cursor, before, pending, err := s.reconciliationSnapshot(work, r, provider, version)
	if err != nil {
		return delivery.ReconcileResult{}, err
	}
	if err := s.executor.allow(work, r.Binding, caller); err != nil {
		return delivery.ReconcileResult{}, err
	}
	observation, err := lookup.query.Query(work, delivery.OutcomeQuery{TenantID: delivery.TenantID(r.Binding.TenantID), IntentID: delivery.IntentID(r.Binding.RecordID), Generation: r.Generation, ProviderIdempotencyKey: r.Binding.RecordID, Checkpoint: cursor})
	if err != nil {
		return delivery.ReconcileResult{}, err
	}
	if observation.State == delivery.StateTransientFailure {
		return delivery.ReconcileResult{}, delivery.ErrUnavailable
	}
	if observation.State == delivery.StateCancelled && !pending {
		return delivery.ReconcileResult{}, delivery.ErrConflict
	}
	observation.ObservedAt = observation.ObservedAt.UTC().Truncate(time.Microsecond)
	scope.Step++
	scope.Digest = reconciliationCursorDigest(s.keyed.key, scope, observation.Checkpoint)
	actualCursorDigest := scope.Digest
	if observation.State != delivery.StateOutcomeUnknown && observation.State != delivery.StateAccepted {
		scope.Digest = [32]byte{}
	}
	p := reconciliationPrepared{request: request, providerVersion: version, state: observation.State, observed: observation.ObservedAt, retryAfter: observation.RetryAfter, cursorScope: scope}
	p.query = custodyMAC(s.keyed.key, "identity-delivery-query-observation-v1", request[:], keyedFields(strconv.FormatUint(uint64(p.state), 10), p.observed.Format(time.RFC3339Nano), strconv.FormatInt(int64(p.retryAfter), 10), base64.RawURLEncoding.EncodeToString(actualCursorDigest[:])))
	if scope.Digest != ([32]byte{}) {
		p.cursor, err = sealReconciliationCursor(work, e.codec, scope, observation.Checkpoint, e.envelopeKey, e.current)
		if err != nil {
			return delivery.ReconcileResult{}, err
		}
	}
	q := delivery.ReceiptRecordRequest{TenantID: delivery.TenantID(r.Binding.TenantID), IntentID: delivery.IntentID(r.Binding.RecordID), Provider: provider, ProviderEventID: base64.RawURLEncoding.EncodeToString(request[:]), Generation: r.Generation, Status: p.state, ObservedAt: p.observed, IdempotencyKey: string(r.Binding.CommandID)}
	command, err := newReconciliationQueryCommand(r.Binding, q, r.ExpectedStatusVersion, int64(r.ExpectedStep), before, scope.Digest, e.native.store, p)
	if err != nil {
		return delivery.ReconcileResult{}, admissionError(err)
	}
	coordinator, registry, native, err := e.build(&p)
	if err != nil {
		return delivery.ReconcileResult{}, admissionError(err)
	}
	if err := s.executor.allow(work, r.Binding, caller); err != nil {
		return delivery.ReconcileResult{}, err
	}
	committed, err := executeReconciliationQuery(work, coordinator, registry, native, s.executor.retentionVersion, r.Binding, command, r.ExpectedStatusVersion)
	switch committed.Outcome {
	case identity.CommitOutcomeUnknown, identity.CommitOutcomeInProgress:
		return delivery.ReconcileResult{}, delivery.ErrOutcomeUnknown
	case identity.CommitOutcomeConflict:
		return delivery.ReconcileResult{}, delivery.ErrConflict
	case identity.CommitOutcomeCommitted:
		if err != nil {
			return delivery.ReconcileResult{}, delivery.ErrOutcomeUnknown
		}
		result, err := s.reconciliationResult(work, r, version, request)
		if err != nil {
			return delivery.ReconcileResult{}, err
		}
		if err := s.executor.allow(work, r.Binding, caller); err != nil {
			return delivery.ReconcileResult{}, err
		}
		return result, nil
	default:
		if err == nil {
			return delivery.ReconcileResult{}, delivery.ErrUnavailable
		}
		return delivery.ReconcileResult{}, admissionError(err)
	}
}
func reconciliationRequestDigest(s *keyedAdmission, r ReconcileCommandRequest, profile uint64) [32]byte {
	binding := cancellationBindingDigest(r.Binding)
	return custodyMAC(s.key, "identity-delivery-query-request-v1", binding[:], keyedFields(strconv.FormatUint(r.ExpectedStatusVersion, 10), strconv.FormatUint(r.ExpectedStep, 10), strconv.FormatUint(uint64(r.Generation), 10), r.Checkpoint, strconv.FormatUint(profile, 10)))
}
func (s *EnqueueService) reconciliationSnapshot(ctx context.Context, r ReconcileCommandRequest, provider string, profile uint64) (reconciliationCursorScope, string, [32]byte, bool, error) {
	scope := reconciliationCursorScope{Deployment: s.keyed.deployment, Tenant: string(r.Binding.TenantID), Subject: string(r.Binding.UserID), Effect: r.Binding.RecordID, Provider: provider, ProviderVersion: profile, Generation: r.Generation, Step: int64(r.ExpectedStep)}
	var state, version string
	var generation, step, keyVersion int64
	var live, pending bool
	var digest, wire []byte
	var keyID string
	err := s.keyed.pool.QueryRow(ctx, `SELECT i.state,i.status_version::text,p.generation,p.lease_owner IS NOT NULL AND p.lease_until>clock_timestamp(),p.cancel_requested,COALESCE(h.step,0),COALESCE(h.after_digest,decode(repeat('00',32),'hex')),COALESCE(c.key_id,''),COALESCE(c.digest_key_version,0),COALESCE(c.ciphertext,''::bytea) FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id) LEFT JOIN LATERAL(SELECT step,after_digest FROM identity.delivery_reconciliation_checkpoints h WHERE h.deployment=i.deployment AND h.tenant_id=i.tenant_id AND h.effect_id=i.effect_id AND h.generation=p.generation ORDER BY step DESC LIMIT 1) h ON true LEFT JOIN identity.delivery_reconciliation_cursors c ON c.deployment=i.deployment AND c.tenant_id=i.tenant_id AND c.effect_id=i.effect_id AND c.generation=p.generation AND c.step=h.step AND c.cursor_digest=h.after_digest WHERE i.deployment=$1 AND i.tenant_id=$2 AND i.effect_id=$3 AND i.subject_id=$4`, scope.Deployment, scope.Tenant, scope.Effect, scope.Subject).Scan(&state, &version, &generation, &live, &pending, &step, &digest, &keyID, &keyVersion, &wire)
	if errors.Is(err, pgx.ErrNoRows) {
		return scope, "", [32]byte{}, false, delivery.ErrConflict
	}
	if err != nil {
		return scope, "", [32]byte{}, false, attemptFailure(ctx, err)
	}
	if version != strconv.FormatUint(r.ExpectedStatusVersion, 10) || generation != int64(r.Generation) || step != int64(r.ExpectedStep) || live || state != "outcome-unknown" && state != "submitted" || len(digest) != 32 {
		return scope, "", [32]byte{}, false, delivery.ErrConflict
	}
	scope.Digest = [32]byte(digest)
	if r.Checkpoint != reconciliationCursorToken(s.keyed.key, scope) {
		return scope, "", [32]byte{}, false, delivery.ErrConflict
	}
	if scope.Digest == ([32]byte{}) {
		return scope, "", scope.Digest, pending, nil
	}
	if keyVersion < 1 || keyVersion > math.MaxUint32 {
		return scope, "", [32]byte{}, false, delivery.ErrUnavailable
	}
	cursor, err := openReconciliationCursor(ctx, s.reconciliation.codec, scope, reconciliationCursorEnvelope{keyID, uint32(keyVersion), wire})
	if err != nil {
		return scope, "", [32]byte{}, false, err
	}
	if reconciliationCursorDigest(s.keyed.key, scope, cursor) != scope.Digest {
		return scope, "", [32]byte{}, false, delivery.ErrForbidden
	}
	return scope, cursor, scope.Digest, pending, nil
}
func executeReconciliationQuery(ctx context.Context, coordinator *identitypostgres.Coordinator, registry *identitypostgres.ContributorRegistry, native *reconciliationQueryContributor, retention uint64, b identity.CommandBinding, command identity.Command, version uint64) (identity.CommandResult, error) {
	plan, err := reconciliationQueryPlan(coordinator, registry, native, retention, b, command, version)
	if err != nil {
		return identity.CommandResult{}, err
	}
	reservation, result, err := coordinator.ReserveCommand(ctx, b, command, plan)
	if err != nil || reservation == (identitypostgres.Reservation{}) {
		return result, err
	}
	work, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown}, err
	}
	defer coordinator.Abort(work, identity.UnavailableError{})
	provisional, err := coordinator.ApplyFeature(ctx, work, command)
	if err != nil {
		return coordinator.Abort(work, err)
	}
	return coordinator.Commit(work, provisional)
}
func reconciliationQueryPlan(coordinator *identitypostgres.Coordinator, registry *identitypostgres.ContributorRegistry, native *reconciliationQueryContributor, retention uint64, b identity.CommandBinding, command identity.Command, version uint64) (identitypostgres.CommandPlan, error) {
	digest, err := deliveryFeatureAuditDigest(b, ReconcileOperation())
	if err != nil {
		return identitypostgres.CommandPlan{}, err
	}
	plan := identitypostgres.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "delivery_intent", Feature: &identitypostgres.FeatureRegistration{Contributor: native.Descriptor(), Operation: ReconcileOperation()}, Audits: []identitypostgres.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: retention, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "delivery.reconciled.v1", BeforeVersion: version, AfterVersion: version + 1}}
	return coordinator.PrepareCommandPlan(b, command, plan)
}
func (s *EnqueueService) reconciliationResult(ctx context.Context, r ReconcileCommandRequest, profile uint64, request [32]byte) (delivery.ReconcileResult, error) {
	id, _ := base64.RawURLEncoding.DecodeString(string(r.Binding.CommandID))
	var binding, wantRequest, afterDigest []byte
	var before, after, provider, version string
	var generation, step int64
	var state int16
	err := s.keyed.pool.QueryRow(ctx, `SELECT c.binding_digest,q.request_digest,c.before_version::text,c.after_version::text,c.provider,q.provider_version::text,c.generation,c.step,c.after_digest,c.result_state FROM identity.delivery_reconciliation_commands c JOIN identity.delivery_reconciliation_queries q USING(deployment,tenant_id,command_id) WHERE c.deployment=$1 AND c.tenant_id=$2 AND c.command_id=$3 AND c.effect_id=$4 AND c.subject_id=$5`, s.keyed.deployment, string(r.Binding.TenantID), id, r.Binding.RecordID, string(r.Binding.UserID)).Scan(&binding, &wantRequest, &before, &after, &provider, &version, &generation, &step, &afterDigest, &state)
	if err != nil {
		return delivery.ReconcileResult{}, delivery.ErrOutcomeUnknown
	}
	expected := cancellationBindingDigest(r.Binding)
	if !hmac.Equal(binding, expected[:]) || !hmac.Equal(wantRequest, request[:]) || before != strconv.FormatUint(r.ExpectedStatusVersion, 10) || after != strconv.FormatUint(r.ExpectedStatusVersion+1, 10) || version != strconv.FormatUint(profile, 10) || generation != int64(r.Generation) || step != int64(r.ExpectedStep)+1 {
		return delivery.ReconcileResult{}, delivery.ErrConflict
	}
	if len(afterDigest) != 32 || state < 2 || state > 12 {
		return delivery.ReconcileResult{}, delivery.ErrOutcomeUnknown
	}
	scope := reconciliationCursorScope{Deployment: s.keyed.deployment, Tenant: string(r.Binding.TenantID), Subject: string(r.Binding.UserID), Effect: r.Binding.RecordID, Provider: provider, ProviderVersion: profile, Generation: r.Generation, Step: step, Digest: [32]byte(afterDigest)}
	return delivery.ReconcileResult{State: delivery.DeliveryState(state), Checkpoint: reconciliationCursorToken(s.keyed.key, scope)}, nil
}
