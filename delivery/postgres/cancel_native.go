package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

// This native phase is private owned composition, not an authenticated endpoint.
// Its immutable result row belongs to the original command; it has no separate
// reservation, lease, replay state machine or execution authority.
type cancelContributor struct{ store *attemptStore }

var _ identitypostgres.FeatureExecutionContributor = (*cancelContributor)(nil)

func cancelOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/delivery", OperationID: "identity.delivery.cancel", SchemaID: "identity-delivery-cancel-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func (*cancelContributor) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "identity/delivery/postgres", ContractID: "identity.delivery.cancel", Version: 1}
}
func (*cancelContributor) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{cancelOperation()}
}

// The owning admission layer must HMAC the bounded reason with retained secret
// configuration. Neither raw operator text nor an unkeyed reason hash is stored.
func newCancellationCommand(b identity.CommandBinding, generation uint32, version uint64, reason [32]byte) (identity.Command, error) {
	if b.ValidateFor(cancelOperation()) != nil || validateCancellation(delivery.CancelRequest{TenantID: delivery.TenantID(b.TenantID), IntentID: delivery.IntentID(b.RecordID), Reason: "protected-command"}, string(b.UserID)) != nil || version == 0 || version == ^uint64(0) || reason == ([32]byte{}) {
		return identity.Command{}, delivery.ErrInvalidInput
	}
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: cancelOperation(), Fields: []identity.FeatureField{
		{Name: "delivery.generation", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(generation)}},
		{Name: "delivery.reason", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: reason[:]}},
		{Name: "delivery.version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: version}},
	}})
}

func decodeCancellation(command identity.Command) (identity.FeatureCommandSpec, uint32, uint64, error) {
	s, ok := command.Feature()
	if !ok || s.Operation != cancelOperation() || s.Binding.ValidateFor(cancelOperation()) != nil || len(s.Fields) != 3 {
		return s, 0, 0, delivery.ErrInvalidInput
	}
	f := s.Fields
	if f[0].Name != "delivery.generation" || f[0].Value.Kind != identity.FeatureUint64 || f[0].Value.Uint64 > 4294967295 || f[1].Name != "delivery.reason" || f[1].Value.Kind != identity.FeatureBytes || len(f[1].Value.Bytes) != 32 || [32]byte(f[1].Value.Bytes) == ([32]byte{}) || f[2].Name != "delivery.version" || f[2].Value.Kind != identity.FeatureUint64 {
		return s, 0, 0, delivery.ErrInvalidInput
	}
	version := f[2].Value.Uint64
	if version == 0 || version == ^uint64(0) || validateCancellation(delivery.CancelRequest{TenantID: delivery.TenantID(s.Binding.TenantID), IntentID: delivery.IntentID(s.Binding.RecordID), Reason: "protected-command"}, string(s.Binding.UserID)) != nil {
		return s, 0, 0, delivery.ErrInvalidInput
	}
	return s, uint32(f[0].Value.Uint64), version, nil
}

func (c *cancelContributor) ValidateFeatureCommand(command identity.Command, p identitypostgres.CommandPlan) error {
	_, _, version, err := decodeCancellation(command)
	if c == nil || c.store == nil || err != nil || p.Feature == nil || p.Feature.Contributor != c.Descriptor() || p.Feature.Operation != cancelOperation() || p.SubjectType != "delivery_intent" || p.Lifecycle == nil || p.Lifecycle.EventType != "delivery.cancelled.v1" || p.Lifecycle.BeforeVersion != version || p.Lifecycle.AfterVersion != version+1 || len(p.Audits) != 1 || p.Delivery != nil || p.Capability != nil || p.RiskEvidence != nil || p.CommandCounters != nil {
		return delivery.ErrInvalidInput
	}
	a := p.Audits[0]
	if a.EventType != cancelOperation().OperationID || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" || a.RetentionPolicyVersion == 0 {
		return delivery.ErrInvalidInput
	}
	return nil
}

func (c *cancelContributor) ApplyFeature(ctx context.Context, w identitypostgres.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if ctx == nil || c == nil || c.store == nil {
		return identity.FeatureReceipt{}, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, feature, transition, err := w.FeatureScope(c)
	s, generation, version, decoded := decodeCancellation(command)
	if err != nil || decoded != nil || b != s.Binding || feature.Operation != cancelOperation() || feature.Contributor != c.Descriptor() || transition.EventType != "delivery.cancelled.v1" || transition.BeforeVersion != version || transition.AfterVersion != version+1 {
		return identity.FeatureReceipt{}, delivery.ErrForbidden
	}
	sql := cancellationWorkSQL(w)
	var current string
	if err := sql.scan(ctx, `SELECT status_version::text FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND subject_id=$4 FOR UPDATE`, []any{c.store.deployment, string(b.TenantID), b.RecordID, string(b.UserID)}, &current); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
		return identity.FeatureReceipt{}, err
	}
	if current != strconv.FormatUint(version, 10) {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	out, err := c.store.cancelIn(ctx, sql, delivery.CancelRequest{TenantID: delivery.TenantID(b.TenantID), IntentID: delivery.IntentID(b.RecordID), ExpectedGeneration: generation, Reason: "protected-command"}, string(b.UserID), true)
	if err != nil {
		if errors.Is(err, delivery.ErrConflict) || errors.Is(err, delivery.ErrNotFound) {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
		return identity.FeatureReceipt{}, err
	}
	if err := sql.scan(ctx, `SELECT status_version::text FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, []any{c.store.deployment, string(b.TenantID), b.RecordID}, &current); err != nil {
		return identity.FeatureReceipt{}, err
	}
	// A terminal/already-pending command still records one protected observation
	// transition. The trigger increments metadata without changing its outcome or
	// renewing a local-stop time. Original command replay never invokes this path.
	if current == strconv.FormatUint(version, 10) {
		if err := sql.exec(ctx, `UPDATE identity.delivery_intents SET state=state WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, c.store.deployment, string(b.TenantID), b.RecordID); err != nil {
			return identity.FeatureReceipt{}, err
		}
	} else if current != strconv.FormatUint(version+1, 10) {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	digest := cancellationBindingDigest(b)
	if err := sql.exec(ctx, `INSERT INTO identity.delivery_cancellations(deployment,tenant_id,command_id,command_purpose,effect_id,subject_id,binding_digest,generation,before_version,after_version,result_state,local_cancelled) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::numeric,$10::numeric,$11,$12)`, c.store.deployment, string(b.TenantID), id, b.OperationID, b.RecordID, string(b.UserID), digest[:], int64(generation), strconv.FormatUint(version, 10), strconv.FormatUint(version+1, 10), int16(out.State), out.LocalCancelled); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: cancelOperation(), BeforeVersion: version, AfterVersion: version + 1}, nil
}

func cancellationWorkSQL(w identitypostgres.Work) cancellationSQL {
	return cancellationSQL{
		scan: func(ctx context.Context, query string, args []any, dest ...any) error {
			rows, err := w.Query(ctx, query, args...)
			if err != nil {
				return err
			}
			return scanCancellationRow(rows, dest...)
		},
		exec: func(ctx context.Context, query string, args ...any) error {
			_, err := w.Exec(ctx, query, args...)
			return err
		},
	}
}
func scanCancellationRow(rows *identitypostgres.WorkRows, dest ...any) error {
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return pgx.ErrNoRows
	}
	if err := rows.Scan(dest...); err != nil {
		return err
	}
	if rows.Next() {
		return delivery.ErrUnavailable
	}
	return rows.Err()
}
func cancellationBindingDigest(b identity.CommandBinding) [32]byte {
	// Binding contains bounded safe identities/versions only. The kernel owns
	// authentication and the keyed full-command intent; this is scope equality.
	data, _ := json.Marshal(b)
	return sha256.Sum256(data)
}

func (c *cancelContributor) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	if ctx == nil || c == nil || c.store == nil {
		return identitypostgres.RecoveryUnknown, delivery.ErrInvalidInput
	}
	b, f, l, err := w.FeatureScope(c)
	if err != nil || f.Contributor != c.Descriptor() || f.Operation != cancelOperation() || l.EventType != "delivery.cancelled.v1" {
		return identitypostgres.RecoveryUnknown, delivery.ErrForbidden
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	rows, err := w.Query(ctx, `SELECT binding_digest,before_version::text,after_version::text FROM identity.delivery_cancellations WHERE deployment=$1 AND tenant_id=$2 AND command_id=$3 AND effect_id=$4 AND subject_id=$5`, c.store.deployment, string(b.TenantID), id, b.RecordID, string(b.UserID))
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	var digest []byte
	var before, after string
	err = scanCancellationRow(rows, &digest, &before, &after)
	if err == pgx.ErrNoRows {
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

func cancellationAuditDigest(b identity.CommandBinding) ([32]byte, error) {
	return deliveryFeatureAuditDigest(b, cancelOperation())
}
