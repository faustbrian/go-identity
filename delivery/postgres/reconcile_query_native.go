package postgres

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

// ReconcileOperation identifies the protected original-key query schema, not
// authority to query. Construct its binding from authenticated platform scope.
// Its V2 participant adds request/observation commitments while installed native
// V1 command fields, operation plans and migration histories remain unchanged.
func ReconcileOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/delivery", OperationID: "identity.delivery.reconcile", SchemaID: "identity-delivery-query-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

type reconciliationPrepared struct {
	request, query  [32]byte
	providerVersion uint64
	state           delivery.DeliveryState
	observed        time.Time
	retryAfter      time.Duration
	cursorScope     reconciliationCursorScope
	cursor          reconciliationCursorEnvelope
}
type reconciliationQueryContributor struct {
	native   *reconciliationContributor
	codec    *payloadCodec
	prepared *reconciliationPrepared
}

func (*reconciliationQueryContributor) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "identity/delivery/postgres", ContractID: "identity.delivery.reconcile", Version: 2}
}
func (*reconciliationQueryContributor) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{ReconcileOperation()}
}

func newReconciliationQueryCommand(b identity.CommandBinding, q delivery.ReceiptRecordRequest, version uint64, step int64, before, after [32]byte, store *receiptStore, p reconciliationPrepared) (identity.Command, error) {
	if b.ValidateFor(ReconcileOperation()) != nil || p.request == ([32]byte{}) || p.query == ([32]byte{}) {
		return identity.Command{}, delivery.ErrInvalidInput
	}
	legacy := b
	op := reconciliationOperation()
	legacy.OperationID, legacy.SchemaID, legacy.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	command, err := newReconciliationCommand(legacy, q, version, step, before, after, store)
	if err != nil {
		return identity.Command{}, err
	}
	spec, _ := command.Feature()
	spec.Binding = b
	spec.Operation = ReconcileOperation()
	spec.Fields = append(spec.Fields, identity.FeatureField{Name: "delivery.query-request", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.request[:]}}, identity.FeatureField{Name: "delivery.query-evidence", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.query[:]}})
	return identity.NewFeatureCommand(spec)
}
func decodeReconciliationQuery(command identity.Command) (identity.Command, [32]byte, [32]byte, error) {
	spec, ok := command.Feature()
	if !ok || spec.Operation != ReconcileOperation() || spec.Binding.ValidateFor(ReconcileOperation()) != nil || len(spec.Fields) != 12 {
		return identity.Command{}, [32]byte{}, [32]byte{}, delivery.ErrInvalidInput
	}
	var request, evidence [32]byte
	fields := make([]identity.FeatureField, 0, 10)
	for _, f := range spec.Fields {
		if f.Name == "delivery.query-request" || f.Name == "delivery.query-evidence" {
			if f.Value.Kind != identity.FeatureBytes || len(f.Value.Bytes) != 32 {
				return identity.Command{}, request, evidence, delivery.ErrInvalidInput
			}
			if f.Name == "delivery.query-request" {
				request = [32]byte(f.Value.Bytes)
			} else {
				evidence = [32]byte(f.Value.Bytes)
			}
		} else {
			fields = append(fields, f)
		}
	}
	if request == ([32]byte{}) || evidence == ([32]byte{}) || len(fields) != 10 {
		return identity.Command{}, request, evidence, delivery.ErrInvalidInput
	}
	spec.Fields = fields
	spec.Operation = reconciliationOperation()
	spec.Binding.OperationID, spec.Binding.SchemaID, spec.Binding.SchemaVersion = spec.Operation.OperationID, spec.Operation.SchemaID, spec.Operation.SchemaVersion
	legacy, err := identity.NewFeatureCommand(spec)
	if err != nil {
		return legacy, request, evidence, delivery.ErrInvalidInput
	}
	if _, _, _, _, _, _, _, _, err := decodeReconciliation(legacy); err != nil {
		return legacy, request, evidence, err
	}
	return legacy, request, evidence, nil
}
func (c *reconciliationQueryContributor) ValidateFeatureCommand(command identity.Command, p identitypostgres.CommandPlan) error {
	legacy, _, _, err := decodeReconciliationQuery(command)
	if c == nil || c.native == nil || c.codec == nil || err != nil || p.Feature == nil || p.Feature.Contributor != c.Descriptor() || p.Feature.Operation != ReconcileOperation() {
		return delivery.ErrInvalidInput
	}
	copyPlan := p
	feature := *p.Feature
	feature.Contributor = c.native.Descriptor()
	feature.Operation = reconciliationOperation()
	copyPlan.Feature = &feature
	return c.native.ValidateFeatureCommand(legacy, copyPlan)
}
func (c *reconciliationQueryContributor) ApplyFeature(ctx context.Context, w identitypostgres.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if ctx == nil || c == nil || c.native == nil || c.codec == nil || c.prepared == nil {
		return identity.FeatureReceipt{}, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, f, l, err := w.FeatureScope(c)
	legacy, request, query, decoded := decodeReconciliationQuery(command)
	_, q, event, evidence, version, step, before, after, shape := decodeReconciliation(legacy)
	spec, _ := command.Feature()
	if err != nil || decoded != nil || shape != nil || b != spec.Binding || f.Contributor != c.Descriptor() || f.Operation != ReconcileOperation() || l.EventType != "delivery.reconciled.v1" || l.BeforeVersion != version || l.AfterVersion != version+1 {
		return identity.FeatureReceipt{}, delivery.ErrForbidden
	}
	p := c.prepared
	if request != p.request || query != p.query || p.providerVersion == 0 || p.cursorScope.Digest != after || p.cursorScope.Deployment != c.native.store.deployment || p.cursorScope.Tenant != string(b.TenantID) || p.cursorScope.Subject != string(b.UserID) || p.cursorScope.Effect != b.RecordID || p.cursorScope.Provider != q.Provider || p.cursorScope.ProviderVersion != p.providerVersion || p.cursorScope.Generation != q.Generation || p.cursorScope.Step != step+1 || p.state != q.Status || !p.observed.Equal(q.ObservedAt) || p.retryAfter != 0 {
		return identity.FeatureReceipt{}, delivery.ErrForbidden
	}
	if after != ([32]byte{}) {
		if err := verifyReconciliationCursor(c.codec, p.cursorScope, p.cursor); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	sql := cancellationWorkSQL(w)
	out, err := c.native.applyIn(ctx, sql, b, q, event, evidence, version, step, before, after, ReconcileOperation())
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if q.Status == delivery.StateCancelled {
		var pending bool
		if err := sql.scan(ctx, `SELECT cancel_requested FROM identity.delivery_processing WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, []any{c.native.store.deployment, string(b.TenantID), b.RecordID}, &pending); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if !pending {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err := sql.exec(ctx, `INSERT INTO identity.delivery_reconciliation_queries(deployment,tenant_id,command_id,request_digest,query_digest,provider_version,query_state,observed_at,retry_after_ns) VALUES($1,$2,$3,$4,$5,$6::numeric,$7,$8,$9)`, c.native.store.deployment, string(b.TenantID), id, request[:], query[:], strconv.FormatUint(p.providerVersion, 10), int16(p.state), p.observed, int64(p.retryAfter)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	// Superseded cursors must be erased in the same original transaction. Terminal
	// receipt/cancel paths also erase through the forward schema's owned trigger.
	if err := sql.exec(ctx, `DELETE FROM identity.delivery_reconciliation_cursors WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, c.native.store.deployment, string(b.TenantID), b.RecordID); err != nil {
		return identity.FeatureReceipt{}, err
	}
	var state string
	if err := sql.scan(ctx, `SELECT state FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, []any{c.native.store.deployment, string(b.TenantID), b.RecordID}, &state); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if after != ([32]byte{}) && (state == "outcome-unknown" || state == "submitted") {
		v := p.cursor
		if err := sql.exec(ctx, `INSERT INTO identity.delivery_reconciliation_cursors(deployment,tenant_id,effect_id,generation,step,provider,provider_version,cursor_digest,key_id,digest_key_version,ciphertext) VALUES($1,$2,$3,$4,$5,$6,$7::numeric,$8,$9,$10,$11)`, c.native.store.deployment, string(b.TenantID), b.RecordID, int64(q.Generation), step+1, q.Provider, strconv.FormatUint(p.providerVersion, 10), after[:], v.KeyID, int64(v.KeyVersion), v.Wire); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return out, nil
}
func (c *reconciliationQueryContributor) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	if ctx == nil || c == nil || c.native == nil {
		return identitypostgres.RecoveryUnknown, delivery.ErrInvalidInput
	}
	b, f, l, err := w.FeatureScope(c)
	if err != nil || f.Contributor != c.Descriptor() || f.Operation != ReconcileOperation() || l.EventType != "delivery.reconciled.v1" {
		return identitypostgres.RecoveryUnknown, delivery.ErrForbidden
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	rows, err := w.Query(ctx, `SELECT c.binding_digest,c.before_version::text,c.after_version::text,q.request_digest,q.query_digest FROM identity.delivery_reconciliation_commands c LEFT JOIN identity.delivery_reconciliation_queries q USING(deployment,tenant_id,command_id) WHERE c.deployment=$1 AND c.tenant_id=$2 AND c.command_id=$3 AND c.effect_id=$4 AND c.subject_id=$5`, c.native.store.deployment, string(b.TenantID), id, b.RecordID, string(b.UserID))
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	var binding, request, evidence []byte
	var before, after string
	err = scanCancellationRow(rows, &binding, &before, &after, &request, &evidence)
	if errors.Is(err, pgx.ErrNoRows) {
		return identitypostgres.RecoveryNotCommitted, nil
	}
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	expected := cancellationBindingDigest(b)
	if !hmac.Equal(binding, expected[:]) || before != strconv.FormatUint(l.BeforeVersion, 10) || after != strconv.FormatUint(l.AfterVersion, 10) || len(request) != 32 || len(evidence) != 32 {
		return identitypostgres.RecoveryUnknown, delivery.ErrConflict
	}
	return identitypostgres.RecoveryCommitted, nil
}
