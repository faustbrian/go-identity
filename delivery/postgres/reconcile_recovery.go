package postgres

import (
	"context"
	"errors"
	"strconv"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

// RecoverReconciliation observes or recovers only the original protected query
// command under current exact target/provider/service-account policy. It never
// queries a provider, decrypts cursor/payload, replays a mutation or manufactures
// replacement work. Live pending remains pending. Expired reservations may be
// classified not-committed only through the sole kernel coordinator's unanimous
// participant evidence and protected failure audit. A valid terminal failure
// record may accompany its classified error. Missing/foreign/unsupported-schema
// history fails closed; no historical result grants current authority. Selected
// reconciliation defaults its owned recovery QueryPolicy to current authorize;
// an explicit Coordinator.QueryPolicy is retained. The borrowed dependencies
// and whole-call timeout are the same as Reconcile. Concurrent calls are safe.
func (s *EnqueueService) RecoverReconciliation(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (identitypostgres.CommandRecord, error) {
	if ctx == nil || s == nil || s.executor == nil || s.keyed == nil || s.keyed.pool == nil || s.reconciliation == nil || s.reconciliation.coordinator == nil {
		return identitypostgres.CommandRecord{}, delivery.ErrInvalidInput
	}
	op := ReconcileOperation()
	b := identity.CommandBinding{CommandID: q.CommandID, TenantID: q.TenantID, UserID: q.UserID, ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: q.OperationID, RecordID: q.RecordID, LinkMode: q.LinkMode, PolicyID: s.executor.policyID, PolicyVersion: s.executor.policyVersion, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, CorrelationID: caller.CorrelationID}
	if b.ValidateFor(op) != nil {
		return identitypostgres.CommandRecord{}, delivery.ErrInvalidInput
	}
	work, stop := context.WithTimeout(ctx, s.executor.timeout)
	defer stop()
	scoped, err := cancellationScope(caller, delivery.IntentID(q.RecordID))
	if err != nil {
		return identitypostgres.CommandRecord{}, err
	}
	if err := s.executor.allow(work, b, scoped); err != nil {
		return identitypostgres.CommandRecord{}, err
	}
	var provider, profile string
	var noop bool
	var bindingAAD []byte
	err = s.keyed.pool.QueryRow(work, `SELECT provider,provider_version::text,no_op,binding_aad FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND subject_id=$4`, s.keyed.deployment, string(q.TenantID), q.RecordID, string(q.UserID)).Scan(&provider, &profile, &noop, &bindingAAD)
	if errors.Is(err, pgx.ErrNoRows) {
		return identitypostgres.CommandRecord{}, delivery.ErrNotFound
	}
	if err != nil {
		return identitypostgres.CommandRecord{}, attemptFailure(work, err)
	}
	if _, err := decodeUserBinding(bindingAAD, s.keyed.deployment, string(q.TenantID), q.RecordID, string(q.UserID)); err != nil {
		return identitypostgres.CommandRecord{}, err
	}
	version, err := strconv.ParseUint(profile, 10, 64)
	if err != nil || noop {
		return identitypostgres.CommandRecord{}, delivery.ErrForbidden
	}
	e := s.reconciliation
	selected, ok := e.providers[reconciliationProviderKey{string(q.TenantID), version}]
	if !ok || selected.actor != q.ActorID || q.ActorKind != authorization.SubjectServiceAccount {
		return identitypostgres.CommandRecord{}, delivery.ErrForbidden
	}
	scoped.Request.Resource.Attributes["delivery.provider"] = authorization.StringValue(provider)
	scoped.Request.Resource.Attributes["delivery.provider_config_version"] = authorization.StringValue(profile)
	if err := s.executor.allow(work, b, scoped); err != nil {
		return identitypostgres.CommandRecord{}, err
	}
	observed, observationError := e.coordinator.ObserveCommandAdmission(work, q, scoped)
	if observationError != nil && observed.Record.Validate() != nil {
		return identitypostgres.CommandRecord{}, admissionError(observationError)
	}
	if observed.Absent {
		return identitypostgres.CommandRecord{}, delivery.ErrNotFound
	}
	if observed.Record.Feature == nil || *observed.Record.Feature != op {
		return identitypostgres.CommandRecord{}, delivery.ErrForbidden
	}
	result, err := e.coordinator.RecoverCommand(work, q, scoped)
	if result != (identitypostgres.CommandRecord{}) && (result.Feature == nil || *result.Feature != op) {
		return identitypostgres.CommandRecord{}, delivery.ErrForbidden
	}
	if policyErr := s.executor.allow(work, b, scoped); policyErr != nil {
		return identitypostgres.CommandRecord{}, policyErr
	}
	return result, admissionError(err)
}
