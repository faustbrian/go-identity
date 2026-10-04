package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

// Private owned composition, not an authenticated callback endpoint. Its result
// is an immutable domain projection of the sole kernel command, not a journal.
type receiptContributor struct{ store *receiptStore }

var _ identitypostgres.FeatureExecutionContributor = (*receiptContributor)(nil)

func receiptOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/delivery", OperationID: "identity.delivery.receipt-record", SchemaID: "identity-delivery-receipt-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func (*receiptContributor) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "identity/delivery/postgres", ContractID: "identity.delivery.receipt-record", Version: 1}
}
func (*receiptContributor) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{receiptOperation()}
}

func newReceiptCommand(b identity.CommandBinding, q delivery.ReceiptRecordRequest, version uint64, store *receiptStore) (identity.Command, error) {
	if store == nil || !safeID(store.deployment, false) || store.namespaceKey == ([32]byte{}) || b.ValidateFor(receiptOperation()) != nil || q.Validate() != nil || string(q.TenantID) != string(b.TenantID) || string(q.IntentID) != b.RecordID || validateCancellation(delivery.CancelRequest{TenantID: q.TenantID, IntentID: q.IntentID, Reason: "provider-receipt"}, string(b.UserID)) != nil || version == 0 || version == ^uint64(0) {
		return identity.Command{}, delivery.ErrInvalidInput
	}
	event, evidence := store.digests(q)
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: receiptOperation(), Fields: []identity.FeatureField{
		{Name: "delivery.evidence", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: evidence[:]}},
		{Name: "delivery.event", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: event[:]}},
		{Name: "delivery.generation", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(q.Generation)}},
		{Name: "delivery.observed", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: q.ObservedAt.UTC().Truncate(time.Microsecond)}},
		{Name: "delivery.provider", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: q.Provider}},
		{Name: "delivery.status", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(q.Status)}},
		{Name: "delivery.version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: version}},
	}})
}

func decodeReceiptCommand(command identity.Command) (identity.FeatureCommandSpec, delivery.ReceiptRecordRequest, [32]byte, [32]byte, uint64, error) {
	s, ok := command.Feature()
	fail := func() (identity.FeatureCommandSpec, delivery.ReceiptRecordRequest, [32]byte, [32]byte, uint64, error) {
		return s, delivery.ReceiptRecordRequest{}, [32]byte{}, [32]byte{}, 0, delivery.ErrInvalidInput
	}
	if !ok || s.Operation != receiptOperation() || s.Binding.ValidateFor(receiptOperation()) != nil || len(s.Fields) != 7 {
		return fail()
	}
	names := []string{"delivery.event", "delivery.evidence", "delivery.generation", "delivery.observed", "delivery.provider", "delivery.status", "delivery.version"}
	kinds := []identity.FeatureKind{identity.FeatureBytes, identity.FeatureBytes, identity.FeatureUint64, identity.FeatureTime, identity.FeatureText, identity.FeatureUint64, identity.FeatureUint64}
	for i, f := range s.Fields {
		if f.Name != names[i] || f.Value.Kind != kinds[i] {
			return fail()
		}
	}
	f := s.Fields
	if len(f[0].Value.Bytes) != 32 || len(f[1].Value.Bytes) != 32 || f[2].Value.Uint64 == 0 || f[2].Value.Uint64 > 4294967295 || f[5].Value.Uint64 > 12 || f[6].Value.Uint64 == 0 || f[6].Value.Uint64 == ^uint64(0) {
		return fail()
	}
	event, evidence := [32]byte(f[0].Value.Bytes), [32]byte(f[1].Value.Bytes)
	q := delivery.ReceiptRecordRequest{TenantID: delivery.TenantID(s.Binding.TenantID), IntentID: delivery.IntentID(s.Binding.RecordID), Provider: f[4].Value.Text, ProviderEventID: "protected-provider-event", Generation: uint32(f[2].Value.Uint64), Status: delivery.DeliveryState(f[5].Value.Uint64), ObservedAt: f[3].Value.Time, IdempotencyKey: "protected-receipt-command"}
	if event == ([32]byte{}) || evidence == ([32]byte{}) || q.Validate() != nil || validateCancellation(delivery.CancelRequest{TenantID: q.TenantID, IntentID: q.IntentID, Reason: "provider-receipt"}, string(s.Binding.UserID)) != nil {
		return fail()
	}
	return s, q, event, evidence, f[6].Value.Uint64, nil
}

func (c *receiptContributor) ValidateFeatureCommand(command identity.Command, p identitypostgres.CommandPlan) error {
	_, _, _, _, version, err := decodeReceiptCommand(command)
	if c == nil || c.store == nil || err != nil || p.Feature == nil || p.Feature.Contributor != c.Descriptor() || p.Feature.Operation != receiptOperation() || p.SubjectType != "delivery_intent" || p.Lifecycle == nil || p.Lifecycle.EventType != "delivery.receipt-recorded.v1" || p.Lifecycle.BeforeVersion != version || p.Lifecycle.AfterVersion != version+1 || len(p.Audits) != 1 || p.Delivery != nil || p.Capability != nil || p.RiskEvidence != nil || p.CommandCounters != nil {
		return delivery.ErrInvalidInput
	}
	a := p.Audits[0]
	if a.EventType != receiptOperation().OperationID || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" || a.RetentionPolicyVersion == 0 {
		return delivery.ErrInvalidInput
	}
	return nil
}

func (c *receiptContributor) ApplyFeature(ctx context.Context, w identitypostgres.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if ctx == nil || c == nil || c.store == nil {
		return identity.FeatureReceipt{}, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, f, l, err := w.FeatureScope(c)
	s, q, event, evidence, version, decoded := decodeReceiptCommand(command)
	if err != nil || decoded != nil || b != s.Binding || f.Contributor != c.Descriptor() || f.Operation != receiptOperation() || l.EventType != "delivery.receipt-recorded.v1" || l.BeforeVersion != version || l.AfterVersion != version+1 {
		return identity.FeatureReceipt{}, delivery.ErrForbidden
	}
	sql := cancellationWorkSQL(w)
	var current string
	err = sql.scan(ctx, `SELECT status_version::text FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND subject_id=$4 FOR UPDATE`, []any{c.store.deployment, string(b.TenantID), b.RecordID, string(b.UserID)}, &current)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && current != strconv.FormatUint(version, 10) {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	out, err := c.store.recordEvidenceIn(ctx, sql, q, string(b.UserID), event, evidence)
	if err != nil {
		if errors.Is(err, delivery.ErrConflict) || errors.Is(err, delivery.ErrNotFound) {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
		return identity.FeatureReceipt{}, err
	}
	if err := sql.scan(ctx, `SELECT status_version::text FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, []any{c.store.deployment, string(b.TenantID), b.RecordID}, &current); err != nil {
		return identity.FeatureReceipt{}, err
	}
	// A deduped/earlier observation gets one protected observation transition.
	// Kernel replay never enters this path or renews status metadata.
	if current == strconv.FormatUint(version, 10) {
		if err := sql.exec(ctx, `UPDATE identity.delivery_intents SET state=state WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, c.store.deployment, string(b.TenantID), b.RecordID); err != nil {
			return identity.FeatureReceipt{}, err
		}
	} else if current != strconv.FormatUint(version+1, 10) {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	digest := cancellationBindingDigest(b)
	if err := sql.exec(ctx, `INSERT INTO identity.delivery_receipt_commands(deployment,tenant_id,command_id,command_purpose,effect_id,subject_id,binding_digest,provider,event_digest,evidence_digest,generation,before_version,after_version,result_state,advanced,deduplicated) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::numeric,$13::numeric,$14,$15,$16)`, c.store.deployment, string(b.TenantID), id, b.OperationID, b.RecordID, string(b.UserID), digest[:], q.Provider, event[:], evidence[:], int64(q.Generation), strconv.FormatUint(version, 10), strconv.FormatUint(version+1, 10), int16(out.State), out.Advanced, out.Deduplicated); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: receiptOperation(), BeforeVersion: version, AfterVersion: version + 1}, nil
}

func (c *receiptContributor) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	if ctx == nil || c == nil || c.store == nil {
		return identitypostgres.RecoveryUnknown, delivery.ErrInvalidInput
	}
	b, f, l, err := w.FeatureScope(c)
	if err != nil || f.Contributor != c.Descriptor() || f.Operation != receiptOperation() || l.EventType != "delivery.receipt-recorded.v1" {
		return identitypostgres.RecoveryUnknown, delivery.ErrForbidden
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	rows, err := w.Query(ctx, `SELECT binding_digest,before_version::text,after_version::text FROM identity.delivery_receipt_commands WHERE deployment=$1 AND tenant_id=$2 AND command_id=$3 AND effect_id=$4 AND subject_id=$5`, c.store.deployment, string(b.TenantID), id, b.RecordID, string(b.UserID))
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
