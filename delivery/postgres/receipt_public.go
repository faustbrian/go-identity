package postgres

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

// ReceiptKeyProfile binds a nonzero 32-byte HMAC-SHA256 callback key to one
// tenant, retained provider configuration and service-account actor. IDs are
// bounded printable ASCII; Provider uses the core canonical provider name.
// Version must match Custody.ProviderProfiles; both UTC validity times are
// required and define a half-open interval. Retire credentials by their expiry
// or constructing composition without them; historical events grant no bypass.
// Callers own configuration and must not mutate it during construction.
type ReceiptKeyProfile struct {
	TenantID              delivery.TenantID
	Provider              string
	ProviderConfigVersion uint64
	ActorID               identity.ActorID
	KeyID                 string
	Key                   [32]byte
	NotBefore, NotAfter   time.Time
}

// ReceiptAuthenticationConfig opts into Golib's signed callback profile, not
// a vendor signature approximation. Profiles has 1..32 unique scoped key IDs;
// copied credentials may overlap during rotation. MaxBodyBytes defaults to
// 16KiB; explicit values are 256..65536. Clock defaults to clock.System and must
// be a trusted, concurrency-safe, nonblocking clock, not callback input.
// A fresh signature expires in five minutes with thirty seconds future skew.
// Delayed observations need fresh envelopes, never a renewed retired key.
type ReceiptAuthenticationConfig struct {
	Profiles     []ReceiptKeyProfile
	MaxBodyBytes int
	Clock        clock.Clock
}

// SignedReceiptCallback carries untrusted owned-profile evidence. Signature is
// the exact 32-byte v1 HMAC described in README, not hex text. All routing fields
// and canonical UTC SignedAt are signed with exact Body bytes. Body has seven
// closed receipt fields and no command identity. Bound transport reads before
// allocating Body; this method also bounds it before hashing or parsing.
// Caller retains bytes and must not mutate them until the call returns.
type SignedReceiptCallback struct {
	TenantID              delivery.TenantID
	Provider              string
	ProviderConfigVersion uint64
	KeyID                 string
	SignedAt              time.Time
	Body                  []byte
	Signature             [32]byte
}

// ReceiptCommandRequest combines untrusted callback evidence with trusted
// platform command scope. Binding targets the exact tenant/effect/user and the
// configured provider service-account actor. ActorScope supplies current policy,
// not authentication. Freeze ExpectedStatusVersion and command identity before
// first submission; retries preserve body and fences but may freshly sign the
// same body. IDs, signatures and prior successful results alone grant no policy.
type ReceiptCommandRequest struct {
	Binding               identity.CommandBinding
	ActorScope            authorization.DecisionContext
	ExpectedStatusVersion uint64
	Callback              SignedReceiptCallback
}

// ReceiptOperation identifies the protected operation/schema, not authority.
func ReceiptOperation() identity.FeatureOperation { return receiptOperation() }

func (ReceiptKeyProfile) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("delivery.postgres.ReceiptKeyProfile(redacted)"))
}
func (ReceiptKeyProfile) LogValue() slog.Value {
	return slog.StringValue("delivery.postgres.ReceiptKeyProfile(redacted)")
}

// MarshalJSON forbids implicit key-custody serialization.
func (ReceiptKeyProfile) MarshalJSON() ([]byte, error) {
	return nil, delivery.ErrSerializationForbidden
}
func (ReceiptAuthenticationConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("delivery.postgres.ReceiptAuthenticationConfig(redacted)"))
}
func (ReceiptAuthenticationConfig) LogValue() slog.Value {
	return slog.StringValue("delivery.postgres.ReceiptAuthenticationConfig(redacted)")
}

// MarshalJSON forbids implicit credential configuration serialization.
func (ReceiptAuthenticationConfig) MarshalJSON() ([]byte, error) {
	return nil, delivery.ErrSerializationForbidden
}
func (SignedReceiptCallback) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("delivery.postgres.SignedReceiptCallback(redacted)"))
}
func (SignedReceiptCallback) LogValue() slog.Value {
	return slog.StringValue("delivery.postgres.SignedReceiptCallback(redacted)")
}

// MarshalJSON forbids implicit raw callback/signature serialization.
func (SignedReceiptCallback) MarshalJSON() ([]byte, error) {
	return nil, delivery.ErrSerializationForbidden
}
func (ReceiptCommandRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("delivery.postgres.ReceiptCommandRequest(redacted)"))
}
func (ReceiptCommandRequest) LogValue() slog.Value {
	return slog.StringValue("delivery.postgres.ReceiptCommandRequest(redacted)")
}

// MarshalJSON forbids implicit sensitive command serialization.
func (ReceiptCommandRequest) MarshalJSON() ([]byte, error) {
	return nil, delivery.ErrSerializationForbidden
}

type receiptExecutor struct {
	coordinator *identitypostgres.Coordinator
	registry    *identitypostgres.ContributorRegistry
	native      *receiptContributor
	auth        *receiptAuthenticator
	clock       clock.Clock
}

func receiptConfiguration(c EnqueueConfig) (*receiptAuthenticator, clock.Clock, error) {
	if c.Receipts == nil {
		return nil, nil, nil
	}
	if !c.StateTracking || len(c.Receipts.Profiles) == 0 || len(c.Receipts.Profiles) > 32 {
		return nil, nil, delivery.ErrInvalidInput
	}
	maximum := c.Receipts.MaxBodyBytes
	if maximum == 0 {
		maximum = 16384
	}
	profiles := make([]receiptAuthProfile, len(c.Receipts.Profiles))
	for i, p := range c.Receipts.Profiles {
		retained, ok := c.Custody.ProviderProfiles[p.ProviderConfigVersion]
		if !ok || retained.Provider != p.Provider {
			return nil, nil, delivery.ErrInvalidInput
		}
		profiles[i] = receiptAuthProfile{Tenant: string(p.TenantID), Provider: p.Provider, Version: p.ProviderConfigVersion, Actor: string(p.ActorID), KeyID: p.KeyID, Key: p.Key, NotBefore: p.NotBefore, NotAfter: p.NotAfter}
	}
	auth, err := newReceiptAuthenticator(c.Custody.Deployment, profiles, maximum)
	if err != nil {
		return nil, nil, err
	}
	source := c.Receipts.Clock
	if source == nil {
		source = clock.System{}
	}
	return auth, source, nil
}

func (e *receiptExecutor) authenticate(ctx context.Context, callback SignedReceiptCallback) (q delivery.ReceiptRecordRequest, actor string, err error) {
	defer func() {
		if recover() != nil {
			q, actor, err = delivery.ReceiptRecordRequest{}, "", delivery.ErrUnavailable
		}
	}()
	if e == nil || e.auth == nil || e.clock == nil {
		return q, "", delivery.ErrInvalidInput
	}
	now := e.clock.Now().UTC()
	if !receiptUTCTime(now) {
		return q, "", delivery.ErrUnavailable
	}
	return e.auth.verify(ctx, receiptSignedInput{Tenant: string(callback.TenantID), Provider: callback.Provider, Version: callback.ProviderConfigVersion, KeyID: callback.KeyID, SignedAt: callback.SignedAt, Body: callback.Body, Signature: callback.Signature}, now)
}

// RecordReceipt authenticates bounded evidence and current exact policy before
// any reservation. It atomically records event/outcome, erasure, protected audit
// and lifecycle through the sole kernel coordinator; it never invokes a provider.
// Requires Receipts and both receipt migrations. Exact replay returns the original
// command result, not current effect state, after fresh authentication/policy.
// Changed evidence conflicts. Unknown/in-progress requires an exact command retry;
// never reread fences to manufacture a replacement. Whole call uses Timeout;
// an earlier caller deadline wins. Concurrent calls are supported without workers.
func (s *EnqueueService) RecordReceipt(ctx context.Context, r ReceiptCommandRequest) (delivery.ReceiptRecordResult, error) {
	if err := s.startupCheck(ctx); err != nil {
		return delivery.ReceiptRecordResult{}, err
	}
	if ctx == nil || s == nil || s.executor == nil || s.keyed == nil || s.keyed.pool == nil || s.receipts == nil || r.Binding.ValidateFor(receiptOperation()) != nil || r.ExpectedStatusVersion == 0 || r.ExpectedStatusVersion == ^uint64(0) {
		return delivery.ReceiptRecordResult{}, delivery.ErrInvalidInput
	}
	work, stop := context.WithTimeout(ctx, s.executor.timeout)
	defer stop()
	q, actor, err := s.receipts.authenticate(work, r.Callback)
	if err != nil {
		return delivery.ReceiptRecordResult{}, err
	}
	if string(r.Binding.ActorID) != actor || r.Binding.ActorKind != authorization.SubjectServiceAccount || string(r.Binding.TenantID) != string(q.TenantID) || r.Binding.RecordID != string(q.IntentID) {
		return delivery.ReceiptRecordResult{}, delivery.ErrForbidden
	}
	caller, err := cancellationScope(r.ActorScope, q.IntentID)
	if err != nil {
		return delivery.ReceiptRecordResult{}, err
	}
	caller.Request.Resource.Attributes["delivery.provider"] = authorization.StringValue(q.Provider)
	caller.Request.Resource.Attributes["delivery.provider_config_version"] = authorization.StringValue(strconv.FormatUint(r.Callback.ProviderConfigVersion, 10))
	caller.Request.Resource.Attributes["delivery.generation"] = authorization.IntValue(int64(q.Generation))
	if err := s.executor.allow(work, r.Binding, caller); err != nil {
		return delivery.ReceiptRecordResult{}, err
	}
	var provider, version string
	var noop bool
	var aad []byte
	err = s.keyed.pool.QueryRow(work, `SELECT provider,provider_version::text,no_op,binding_aad FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND subject_id=$4`, s.keyed.deployment, string(r.Binding.TenantID), r.Binding.RecordID, string(r.Binding.UserID)).Scan(&provider, &version, &noop, &aad)
	if errors.Is(err, pgx.ErrNoRows) {
		return delivery.ReceiptRecordResult{}, delivery.ErrNotFound
	}
	if err != nil {
		return delivery.ReceiptRecordResult{}, attemptFailure(work, err)
	}
	if _, err := decodeUserBinding(aad, s.keyed.deployment, string(r.Binding.TenantID), r.Binding.RecordID, string(r.Binding.UserID)); err != nil {
		return delivery.ReceiptRecordResult{}, err
	}
	// The selected target's provider/configuration binding is immutable. Checking
	// it before reserve cannot be raced by ordinary intent-state writers.
	if noop || provider != q.Provider || version != strconv.FormatUint(r.Callback.ProviderConfigVersion, 10) {
		return delivery.ReceiptRecordResult{}, delivery.ErrForbidden
	}
	command, err := newReceiptCommand(r.Binding, q, r.ExpectedStatusVersion, s.receipts.native.store)
	if err != nil {
		return delivery.ReceiptRecordResult{}, admissionError(err)
	}
	if _, _, err := s.receipts.authenticate(work, r.Callback); err != nil {
		return delivery.ReceiptRecordResult{}, err
	}
	if err := s.executor.allow(work, r.Binding, caller); err != nil {
		return delivery.ReceiptRecordResult{}, err
	}
	committed, err := s.receipts.execute(work, s.executor.retentionVersion, r.Binding, command, r.ExpectedStatusVersion)
	switch committed.Outcome {
	case identity.CommitOutcomeUnknown, identity.CommitOutcomeInProgress:
		return delivery.ReceiptRecordResult{}, delivery.ErrOutcomeUnknown
	case identity.CommitOutcomeConflict:
		return delivery.ReceiptRecordResult{}, delivery.ErrConflict
	case identity.CommitOutcomeCommitted:
		if err != nil {
			return delivery.ReceiptRecordResult{}, delivery.ErrOutcomeUnknown
		}
		result, err := s.receiptResult(work, r, q)
		if err != nil {
			return delivery.ReceiptRecordResult{}, err
		}
		if _, _, err := s.receipts.authenticate(work, r.Callback); err != nil {
			return delivery.ReceiptRecordResult{}, err
		}
		if err := s.executor.allow(work, r.Binding, caller); err != nil {
			return delivery.ReceiptRecordResult{}, err
		}
		return result, nil
	default:
		if err == nil {
			return delivery.ReceiptRecordResult{}, delivery.ErrUnavailable
		}
		return delivery.ReceiptRecordResult{}, admissionError(err)
	}
}

func (e *receiptExecutor) execute(ctx context.Context, retention uint64, b identity.CommandBinding, command identity.Command, version uint64) (identity.CommandResult, error) {
	digest, err := deliveryFeatureAuditDigest(b, receiptOperation())
	if err != nil {
		return identity.CommandResult{}, delivery.ErrUnavailable
	}
	plan := identitypostgres.CommandPlan{Contributors: e.registry.Descriptors(), SubjectType: "delivery_intent", Feature: &identitypostgres.FeatureRegistration{Contributor: e.native.Descriptor(), Operation: receiptOperation()}, Audits: []identitypostgres.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: retention, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "delivery.receipt-recorded.v1", BeforeVersion: version, AfterVersion: version + 1}}
	plan, err = e.coordinator.PrepareCommandPlan(b, command, plan)
	if err != nil {
		return identity.CommandResult{}, err
	}
	reservation, result, err := e.coordinator.ReserveCommand(ctx, b, command, plan)
	if err != nil || reservation == (identitypostgres.Reservation{}) {
		return result, err
	}
	work, err := e.coordinator.Begin(ctx, reservation)
	if err != nil {
		return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: receiptOperation()}}, err
	}
	defer e.coordinator.Abort(work, identity.UnavailableError{})
	provisional, err := e.coordinator.ApplyFeature(ctx, work, command)
	if err != nil {
		return e.coordinator.Abort(work, err)
	}
	return e.coordinator.Commit(work, provisional)
}

func (s *EnqueueService) receiptResult(ctx context.Context, r ReceiptCommandRequest, q delivery.ReceiptRecordRequest) (delivery.ReceiptRecordResult, error) {
	id, _ := base64.RawURLEncoding.DecodeString(string(r.Binding.CommandID))
	var binding, event, evidence []byte
	var generation int64
	var before, after, provider string
	var state int16
	var advanced, dedup bool
	err := s.keyed.pool.QueryRow(ctx, `SELECT binding_digest,event_digest,evidence_digest,generation,before_version::text,after_version::text,provider,result_state,advanced,deduplicated FROM identity.delivery_receipt_commands WHERE deployment=$1 AND tenant_id=$2 AND command_id=$3 AND effect_id=$4 AND subject_id=$5`, s.keyed.deployment, string(r.Binding.TenantID), id, r.Binding.RecordID, string(r.Binding.UserID)).Scan(&binding, &event, &evidence, &generation, &before, &after, &provider, &state, &advanced, &dedup)
	expectedBinding := cancellationBindingDigest(r.Binding)
	expectedEvent, expectedEvidence := s.receipts.native.store.digests(q)
	if err != nil || !hmac.Equal(binding, expectedBinding[:]) || !hmac.Equal(event, expectedEvent[:]) || !hmac.Equal(evidence, expectedEvidence[:]) || generation != int64(q.Generation) || before != strconv.FormatUint(r.ExpectedStatusVersion, 10) || after != strconv.FormatUint(r.ExpectedStatusVersion+1, 10) || provider != q.Provider || state < 2 || state > 12 || dedup && advanced {
		return delivery.ReceiptRecordResult{}, delivery.ErrOutcomeUnknown
	}
	return delivery.ReceiptRecordResult{State: delivery.DeliveryState(state), Advanced: advanced, Deduplicated: dedup}, nil
}
