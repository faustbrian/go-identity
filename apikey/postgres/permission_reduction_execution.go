package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

var _ apikey.Store = (*PermissionReductionStore)(nil)

func (s *PermissionReductionStore) validateDecision(d apikey.PermissionReductionDecision) error {
	if s == nil || s.primary == nil || s.primary.config == nil || d.Validate() != nil {
		return apikey.ErrInvalid
	}
	profile := s.primary.config().Configuration.Spec()
	if !s.owns(d.Owner) || d.ConfigurationAuthority.ConfigurationID != profile.ID || d.PolicyVersion != s.primary.config().PolicyVersion || d.Disposition != apikey.PermissionReductionNarrow {
		return apikey.ErrDenied
	}
	return nil
}

func (s *PermissionReductionStore) phase(d apikey.PermissionReductionDecision, actorVersion uint64) (*reductionPhase, error) {
	c := s.primary.config()
	op := s.operation()
	binding := identity.CommandBinding{CommandID: d.CommandID, TenantID: s.config.TenantID, UserID: s.config.UserID, ActorID: s.config.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, RecordID: string(d.KeyID), SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, CorrelationID: string(d.CommandID)}
	if s.organizationID != "" {
		binding.AnonymousFlowID = string(d.CommandID)
	}
	wire, err := json.Marshal(struct {
		Decision       reductionDecisionWire
		Configuration  apikey.ConfigurationSpec
		ActorNamespace string
	}{reductionWire(d), c.Configuration.Spec(), s.config.ActorPolicyNamespace})
	if err != nil {
		return nil, apikey.ErrInvalid
	}
	digest := sha256.Sum256(wire)
	original, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: []identity.FeatureField{{Name: "apikey.reduction.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}}})
	if err != nil {
		return nil, err
	}
	p := &reductionPhase{store: s, decision: d, binding: binding, original: original, actorVersion: actorVersion}
	p.coordinator, p.registry, err = s.primary.compose(p)
	return p, err
}

// ApplyPermissionReduction compares one original decision with actual current
// selected owner/key/configuration/policy facts, fences owner and maintenance actor,
// and commits the strict reduction through the existing coordinator. It performs
// no verification, quota debit or raw-secret operation. Matching original retry
// conserves retained preparation/effects; it cannot re-decide today's target.
// Unknown/in-progress results expose a typed original handle only when the sole
// coordinator actually captured its fingerprint. Retain the exact decision too:
// missing pre-Apply effects cannot prove noncommit or recreate original intent.
func (s *PermissionReductionStore) ApplyPermissionReduction(ctx context.Context, d apikey.PermissionReductionDecision) (out apikey.PermissionReductionResult, err error) {
	if ctx == nil {
		return out, apikey.ErrInvalid
	}
	if validationErr := s.validateDecision(d); validationErr != nil {
		return out, validationErr
	}
	// Freeze caller-owned slices before any callback or SQL.
	d, err = reductionWire(d).decision()
	if err != nil {
		return out, err
	}
	ctx, stop := context.WithTimeout(ctx, s.primary.config().MaximumDuration)
	defer stop()
	var captured [32]byte
	defer func() {
		if recover() != nil {
			out = apikey.PermissionReductionResult{Decision: d, Outcome: identity.CommitOutcomeUnknown}
			err = reductionUnknown(d.CommandID, s.config.TenantID, captured)
		}
	}()
	actorVersion, err := s.authorizeActor(ctx)
	if err != nil {
		return out, err
	}
	p, err := s.phase(d, actorVersion)
	if err != nil {
		return out, nativeError(ctx, err)
	}
	plan, err := p.plan()
	if err != nil {
		return out, nativeError(ctx, err)
	}
	var receipt identity.CommandResult
	var fingerprint [32]byte
	var executionErr error
	if s.organizationID != "" {
		receipt, fingerprint, executionErr = p.coordinator.ExecutePreparedOrganizationAPIKeyPermissionReduction(ctx, p.original, plan)
	} else {
		receipt, fingerprint, executionErr = p.coordinator.ExecutePreparedAPIKeyPermissionReduction(ctx, p.original, plan)
	}
	captured = fingerprint
	out = apikey.PermissionReductionResult{Decision: d, Outcome: receipt.Outcome}
	if receipt.Validate() != nil || receipt.Binding != p.binding || receipt.Feature == nil || receipt.Feature.Operation != s.operation() {
		out.Outcome = identity.CommitOutcomeUnknown
		return out, reductionUnknown(d.CommandID, s.config.TenantID, captured)
	}
	if receipt.Outcome == identity.CommitOutcomeUnknown || receipt.Outcome == identity.CommitOutcomeInProgress {
		return out, reductionUnknown(d.CommandID, s.config.TenantID, captured)
	}
	if receipt.Outcome != identity.CommitOutcomeCommitted {
		return out, nativeError(ctx, executionErr)
	}
	if receipt.Feature.BeforeVersion != d.ExpectedKeyVersion || receipt.Feature.AfterVersion != d.ExpectedKeyVersion+1 {
		out.Outcome = identity.CommitOutcomeUnknown
		return out, reductionUnknown(d.CommandID, s.config.TenantID, captured)
	}
	retained, err := s.readEffect(ctx, d.CommandID, captured)
	if err != nil || !sameReductionDecision(retained.Decision, d) {
		// The acknowledged coordinator receipt still proves commitment. Failure
		// to retrieve safe result metadata must not relabel it Unknown/noncommit
		// or grant a record; retain the exact decision for an original retry.
		if err != nil {
			return out, nativeError(ctx, err)
		}
		return out, identity.UnavailableError{}
	}
	return retained, nativeError(ctx, executionErr)
}

func reductionUnknown(command identity.CommandID, tenant identity.TenantID, fingerprint [32]byte) error {
	query := apikey.PermissionReductionReconcileQuery{CommandID: command, TenantID: tenant, Fingerprint: fingerprint}
	if query.Validate() != nil {
		return identity.UnknownCommitError{CommandID: command}
	}
	return apikey.PermissionReductionUnknownError{Recovery: query}
}

// ReconcilePermissionReduction reports only exact retained original metadata
// under this Store's fixed current authorized service scope. It never verifies
// a credential, reads today's key to reconstruct history, generates preparation,
// retries a decision or debits/refills quota. Absent pre-Apply effect remains
// Unknown with no fabricated decision/result. Keep the original decision for an
// exact original retry; absence never proves rollback or permits a new command.
func (s *PermissionReductionStore) ReconcilePermissionReduction(ctx context.Context, q apikey.PermissionReductionReconcileQuery) (out apikey.PermissionReductionResult, err error) {
	if s == nil || s.primary == nil || s.primary.config == nil || ctx == nil || q.Validate() != nil || q.TenantID != s.config.TenantID {
		return out, apikey.ErrInvalid
	}
	ctx, stop := context.WithTimeout(ctx, s.primary.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out = apikey.PermissionReductionResult{}
			err = identity.UnknownCommitError{CommandID: q.CommandID}
		}
	}()
	actorVersion, err := s.authorizeActor(ctx)
	if err != nil {
		return out, err
	}
	retained, err := s.readEffect(ctx, q.CommandID, q.Fingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, identity.UnknownCommitError{CommandID: q.CommandID}
	}
	if err != nil {
		return out, nativeError(ctx, err)
	}
	p, err := s.phase(retained.Decision, actorVersion)
	if err != nil {
		return out, nativeError(ctx, err)
	}
	query := p.query()
	receipt, err := p.coordinator.RecoverFeatureCommand(ctx, query, p.caller())
	if err != nil || receipt.Validate() != nil || receipt.Binding != p.binding || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil || receipt.Feature.Operation != s.operation() || receipt.Feature.BeforeVersion != retained.Decision.ExpectedKeyVersion || receipt.Feature.AfterVersion != retained.Decision.ExpectedKeyVersion+1 {
		return out, identity.UnknownCommitError{CommandID: q.CommandID}
	}
	return retained, nil
}

func (p *reductionPhase) query() identity.RecoveryQuery {
	b := p.binding
	return identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, AnonymousFlowID: b.AnonymousFlowID, RecordID: b.RecordID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID}
}
func (p *reductionPhase) caller() authorization.DecisionContext {
	b := p.binding
	resource := authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}
	if p.store.organizationID != "" {
		resource.Type, resource.ID = "identity.anonymous-flow", authorization.ResourceID(b.AnonymousFlowID)
	}
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(b.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: b.ActorKind, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: resource}}
}

type reductionEffect struct {
	Schema               uint16
	ActorNamespace       string
	Decision             reductionDecisionWire
	Record               []byte
	ConfigurationVersion uint64
}

func (p *reductionPhase) persistEffect(ctx context.Context, w kernel.Work, record apikey.Record) error {
	binding, fingerprint, generation, err := w.FeatureCommandIdentity(p)
	if err != nil || binding != p.binding || fingerprint == ([32]byte{}) || generation == 0 {
		return apikey.ErrInvalid
	}
	recordWire, err := encodeRecord(record, p.store.primary.config().Configuration)
	if err != nil {
		return err
	}
	wire, err := json.Marshal(reductionEffect{Schema: 1, ActorNamespace: p.store.config.ActorPolicyNamespace, Decision: reductionWire(p.decision), Record: recordWire, ConfigurationVersion: p.snapshot.Source.ConfigurationVersion + 1})
	if err != nil || len(wire) > maximumCommandEffectBytes {
		return apikey.ErrInvalid
	}
	bound, err := json.Marshal(storedBinding(binding))
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `INSERT INTO identity_api_keys.command_effects(command_id,tenant_id,key_id,binding,fingerprint,generation,record) VALUES($1,$2,$3,$4,$5,$6::numeric,$7)`, string(binding.CommandID), string(binding.TenantID), binding.RecordID, bound, fingerprint[:], strconv.FormatUint(generation, 10), wire)
	if err != nil || n != 1 {
		return identity.UnavailableError{}
	}
	return nil
}

func (s *PermissionReductionStore) decodeEffect(command identity.CommandID, bound, wire []byte) (apikey.PermissionReductionResult, error) {
	var binding storedBinding
	var effect reductionEffect
	if len(wire) > maximumCommandEffectBytes || decodeCanonical(bound, &binding) != nil || decodeCanonical(wire, &effect) != nil || effect.Schema != 1 || effect.ActorNamespace != s.config.ActorPolicyNamespace {
		return apikey.PermissionReductionResult{}, apikey.ErrDenied
	}
	d, err := effect.Decision.decision()
	if err != nil || s.validateDecision(d) != nil || d.CommandID != command {
		return apikey.PermissionReductionResult{}, apikey.ErrDenied
	}
	b := identity.CommandBinding(binding)
	op := s.operation()
	wantFlow := ""
	if s.organizationID != "" {
		wantFlow = string(command)
	}
	if b.ValidateFor(op) != nil || b.CommandID != command || b.TenantID != s.config.TenantID || b.UserID != s.config.UserID || b.AnonymousFlowID != wantFlow || b.ActorID != s.config.ActorID || b.ActorKind != authorization.SubjectServiceAccount || b.RecordID != string(d.KeyID) || b.PolicyID != s.primary.config().PolicyID || b.PolicyVersion != s.primary.config().PolicyVersion || b.CorrelationID != string(command) {
		return apikey.PermissionReductionResult{}, apikey.ErrDenied
	}
	record, err := decodeRecord(effect.Record, s.primary.config().Configuration)
	if err != nil {
		return apikey.PermissionReductionResult{}, identity.UnavailableError{}
	}
	out := apikey.PermissionReductionResult{Decision: d, Outcome: identity.CommitOutcomeCommitted, Record: &record, ConfigurationAuthority: &apikey.ConfigurationAuthorityBinding{TenantID: s.config.TenantID, ConfigurationID: record.ConfigurationID, Version: effect.ConfigurationVersion}}
	if out.Validate(s.primary.config().Configuration) != nil {
		return apikey.PermissionReductionResult{}, identity.UnavailableError{}
	}
	return out, nil
}

func (s *PermissionReductionStore) readEffect(ctx context.Context, command identity.CommandID, fingerprint [32]byte) (apikey.PermissionReductionResult, error) {
	if fingerprint == ([32]byte{}) {
		return apikey.PermissionReductionResult{}, apikey.ErrDenied
	}
	var binding, actual, wire []byte
	err := s.primary.pool.Raw().QueryRow(ctx, `SELECT binding,fingerprint,record FROM identity_api_keys.command_effects WHERE command_id=$1 AND tenant_id=$2`, string(command), string(s.config.TenantID)).Scan(&binding, &actual, &wire)
	if err != nil {
		return apikey.PermissionReductionResult{}, err
	}
	if len(actual) != 32 || !hmac.Equal(actual, fingerprint[:]) {
		return apikey.PermissionReductionResult{}, apikey.ErrDenied
	}
	return s.decodeEffect(command, binding, wire)
}

func (p *reductionPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	binding, feature, _, err := w.FeatureScope(p)
	if err != nil || binding != p.binding || feature.Operation != p.store.operation() {
		return kernel.RecoveryUnknown, apikey.ErrDenied
	}
	rows, err := w.Query(ctx, `SELECT binding,fingerprint,record FROM identity_api_keys.command_effects WHERE command_id=$1 AND tenant_id=$2`, string(binding.CommandID), string(binding.TenantID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, rows.Err()
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var bound, fingerprint, wire []byte
	if rows.Scan(&bound, &fingerprint, &wire) != nil || rows.Next() || rows.Err() != nil || len(fingerprint) != 32 {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	out, err := p.store.decodeEffect(binding.CommandID, bound, wire)
	if err != nil || !sameReductionDecision(out.Decision, p.decision) {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}
