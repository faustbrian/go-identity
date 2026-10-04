package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"math"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

// Already-authenticated local evidence only. The kernel owns reservation,
// journal, audit, lifecycle and transaction; this participant owns their atomic
// delivery projection. Provider queries and raw cursor custody are separate.
type reconciliationContributor struct{ store *receiptStore }

var _ identitypostgres.FeatureExecutionContributor = (*reconciliationContributor)(nil)

func reconciliationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/delivery", OperationID: "identity.delivery.reconcile", SchemaID: "identity-delivery-reconcile-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func (*reconciliationContributor) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "identity/delivery/postgres", ContractID: "identity.delivery.reconcile", Version: 1}
}
func (*reconciliationContributor) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{reconciliationOperation()}
}

func newReconciliationCommand(b identity.CommandBinding, q delivery.ReceiptRecordRequest, version uint64, step int64, before, after [32]byte, store *receiptStore) (identity.Command, error) {
	if b.ValidateFor(reconciliationOperation()) != nil || step < 0 || step == math.MaxInt64 {
		return identity.Command{}, delivery.ErrInvalidInput
	}
	// Reuse the closed receipt evidence contract, changing only operation identity.
	receiptBinding := b
	op := receiptOperation()
	receiptBinding.OperationID, receiptBinding.SchemaID, receiptBinding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	command, err := newReceiptCommand(receiptBinding, q, version, store)
	if err != nil {
		return identity.Command{}, err
	}
	spec, _ := command.Feature()
	spec.Binding, spec.Operation = b, reconciliationOperation()
	spec.Fields = append(spec.Fields,
		identity.FeatureField{Name: "delivery.checkpoint-after", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: after[:]}},
		identity.FeatureField{Name: "delivery.checkpoint-before", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: before[:]}},
		identity.FeatureField{Name: "delivery.checkpoint-step", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(step)}},
	)
	return identity.NewFeatureCommand(spec)
}

func decodeReconciliation(command identity.Command) (identity.FeatureCommandSpec, delivery.ReceiptRecordRequest, [32]byte, [32]byte, uint64, int64, [32]byte, [32]byte, error) {
	spec, ok := command.Feature()
	fail := func() (identity.FeatureCommandSpec, delivery.ReceiptRecordRequest, [32]byte, [32]byte, uint64, int64, [32]byte, [32]byte, error) {
		return spec, delivery.ReceiptRecordRequest{}, [32]byte{}, [32]byte{}, 0, 0, [32]byte{}, [32]byte{}, delivery.ErrInvalidInput
	}
	if !ok || spec.Operation != reconciliationOperation() || spec.Binding.ValidateFor(reconciliationOperation()) != nil || len(spec.Fields) != 10 {
		return fail()
	}
	f := spec.Fields
	if f[0].Name != "delivery.checkpoint-after" || f[1].Name != "delivery.checkpoint-before" || f[2].Name != "delivery.checkpoint-step" || f[0].Value.Kind != identity.FeatureBytes || f[1].Value.Kind != identity.FeatureBytes || f[2].Value.Kind != identity.FeatureUint64 || len(f[0].Value.Bytes) != 32 || len(f[1].Value.Bytes) != 32 || f[2].Value.Uint64 >= math.MaxInt64 {
		return fail()
	}
	receiptSpec := spec
	op := receiptOperation()
	receiptSpec.Operation = op
	receiptSpec.Binding.OperationID, receiptSpec.Binding.SchemaID, receiptSpec.Binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	receiptSpec.Fields = f[3:]
	receiptCommand, err := identity.NewFeatureCommand(receiptSpec)
	if err != nil {
		return fail()
	}
	_, q, event, evidence, version, err := decodeReceiptCommand(receiptCommand)
	if err != nil {
		return fail()
	}
	return spec, q, event, evidence, version, int64(f[2].Value.Uint64), [32]byte(f[1].Value.Bytes), [32]byte(f[0].Value.Bytes), nil
}

func (c *reconciliationContributor) ValidateFeatureCommand(command identity.Command, p identitypostgres.CommandPlan) error {
	_, _, _, _, version, _, _, _, err := decodeReconciliation(command)
	if c == nil || c.store == nil || err != nil || p.Feature == nil || p.Feature.Contributor != c.Descriptor() || p.Feature.Operation != reconciliationOperation() || p.SubjectType != "delivery_intent" || p.Lifecycle == nil || p.Lifecycle.EventType != "delivery.reconciled.v1" || p.Lifecycle.BeforeVersion != version || p.Lifecycle.AfterVersion != version+1 || len(p.Audits) != 1 || p.Delivery != nil || p.Capability != nil || p.RiskEvidence != nil || p.CommandCounters != nil {
		return delivery.ErrInvalidInput
	}
	a := p.Audits[0]
	if a.EventType != reconciliationOperation().OperationID || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" || a.RetentionPolicyVersion == 0 {
		return delivery.ErrInvalidInput
	}
	return nil
}

func (c *reconciliationContributor) ApplyFeature(ctx context.Context, w identitypostgres.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if ctx == nil || c == nil || c.store == nil {
		return identity.FeatureReceipt{}, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, f, l, err := w.FeatureScope(c)
	spec, q, event, evidence, version, step, before, after, decoded := decodeReconciliation(command)
	if err != nil || decoded != nil || b != spec.Binding || f.Contributor != c.Descriptor() || f.Operation != reconciliationOperation() || l.EventType != "delivery.reconciled.v1" || l.BeforeVersion != version || l.AfterVersion != version+1 {
		return identity.FeatureReceipt{}, delivery.ErrForbidden
	}
	return c.applyIn(ctx, cancellationWorkSQL(w), b, q, event, evidence, version, step, before, after, reconciliationOperation())
}

// Only an exact currently invoked feature participant may borrow this phase.
// Both schema versions share the original effect/checkpoint/result owner; no
// helper opens a transaction, queries a provider or registers another journal.
func (c *reconciliationContributor) applyIn(ctx context.Context, sql cancellationSQL, b identity.CommandBinding, q delivery.ReceiptRecordRequest, event, evidence [32]byte, version uint64, step int64, before, after [32]byte, operation identity.FeatureOperation) (identity.FeatureReceipt, error) {
	var current string
	err := sql.scan(ctx, `SELECT status_version::text FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND subject_id=$4 FOR UPDATE`, []any{c.store.deployment, string(b.TenantID), b.RecordID, string(b.UserID)}, &current)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && current != strconv.FormatUint(version, 10) {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	out, err := c.store.reconcileEvidenceIn(ctx, sql, q, string(b.UserID), step, before, after, event, evidence)
	if err != nil {
		if errors.Is(err, delivery.ErrConflict) || errors.Is(err, delivery.ErrNotFound) {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
		return identity.FeatureReceipt{}, err
	}
	if err := sql.scan(ctx, `SELECT status_version::text FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, []any{c.store.deployment, string(b.TenantID), b.RecordID}, &current); err != nil {
		return identity.FeatureReceipt{}, err
	}
	// One protected observation transition even if evidence does not advance the
	// provider status. Kernel replay never executes this participant again.
	if current == strconv.FormatUint(version, 10) {
		if err := sql.exec(ctx, `UPDATE identity.delivery_intents SET state=state WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, c.store.deployment, string(b.TenantID), b.RecordID); err != nil {
			return identity.FeatureReceipt{}, err
		}
	} else if current != strconv.FormatUint(version+1, 10) {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	digest := cancellationBindingDigest(b)
	if err := sql.exec(ctx, `INSERT INTO identity.delivery_reconciliation_commands(deployment,tenant_id,command_id,command_purpose,effect_id,subject_id,binding_digest,provider,event_digest,evidence_digest,generation,step,before_version,after_version,before_digest,after_digest,result_state,advanced,deduplicated) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::numeric,$14::numeric,$15,$16,$17,$18,$19)`, c.store.deployment, string(b.TenantID), id, b.OperationID, b.RecordID, string(b.UserID), digest[:], q.Provider, event[:], evidence[:], int64(q.Generation), step+1, strconv.FormatUint(version, 10), strconv.FormatUint(version+1, 10), before[:], after[:], int16(out.State), out.Advanced, out.Deduplicated); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: operation, BeforeVersion: version, AfterVersion: version + 1}, nil
}

func (c *reconciliationContributor) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	if ctx == nil || c == nil || c.store == nil {
		return identitypostgres.RecoveryUnknown, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	b, f, l, err := w.FeatureScope(c)
	if err != nil || f.Contributor != c.Descriptor() || f.Operation != reconciliationOperation() || l.EventType != "delivery.reconciled.v1" {
		return identitypostgres.RecoveryUnknown, delivery.ErrForbidden
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	rows, err := w.Query(ctx, `SELECT binding_digest,before_version::text,after_version::text FROM identity.delivery_reconciliation_commands WHERE deployment=$1 AND tenant_id=$2 AND command_id=$3 AND effect_id=$4 AND subject_id=$5`, c.store.deployment, string(b.TenantID), id, b.RecordID, string(b.UserID))
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	var digest []byte
	var before, after string
	err = scanCancellationRow(rows, &digest, &before, &after)
	if errors.Is(err, pgx.ErrNoRows) {
		return identitypostgres.RecoveryNotCommitted, nil
	}
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	if len(digest) != 32 || [32]byte(digest) != cancellationBindingDigest(b) || before != strconv.FormatUint(l.BeforeVersion, 10) || after != strconv.FormatUint(l.AfterVersion, 10) {
		return identitypostgres.RecoveryUnknown, delivery.ErrConflict
	}
	return identitypostgres.RecoveryCommitted, nil
}
