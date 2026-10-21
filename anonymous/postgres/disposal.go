package anonymouspostgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func deletionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.delete", SchemaID: "identity.anonymous.delete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// DeletionFields freezes this owner's original lifecycle before fingerprinting.
// It neither authorizes disposal nor selects retention or kernel/session state.
func DeletionFields(subject anonymous.AnonymousSubject) ([]identity.FeatureField, error) {
	f, err := CreationFields(subject)
	if err != nil {
		return nil, err
	}
	for n := range f {
		f[n].Name = strings.Replace(f[n].Name, "anonymous.subject.", "anonymous.delete.", 1)
	}
	return f, nil
}

func deletionSubject(c identity.Command) (anonymous.AnonymousSubject, error) {
	f, ok := c.Feature()
	if !ok || f.Operation != deletionOperation() {
		return anonymous.AnonymousSubject{}, anonymous.ErrInvalidInput
	}
	values := make(map[string]identity.FeatureValue, 7)
	for _, field := range f.Fields {
		if name, owned := strings.CutPrefix(field.Name, "anonymous.delete."); owned {
			values[name] = field.Value
		}
	}
	if len(values) != 7 || values["id"].Kind != identity.FeatureText || values["user"].Kind != identity.FeatureText || values["created"].Kind != identity.FeatureTime || values["expires"].Kind != identity.FeatureTime || values["state"].Kind != identity.FeatureUint64 || values["state"].Uint64 != uint64(anonymous.StateActive) || values["version"].Kind != identity.FeatureUint64 || values["version"].Uint64 != 1 || values["cleanup"].Kind != identity.FeatureUint64 || values["cleanup"].Uint64 < 1 || values["cleanup"].Uint64 > 3 || values["user"].Text != string(f.Binding.UserID) {
		return anonymous.AnonymousSubject{}, anonymous.ErrInvalidInput
	}
	return anonymous.NewAnonymousSubject(anonymous.SubjectSpec{ID: identity.SubjectID(values["id"].Text), TenantID: f.Binding.TenantID, UserID: f.Binding.UserID, CreatedAt: values["created"].Time, ExpiresAt: values["expires"].Time, State: anonymous.StateActive, Version: 1, Cleanup: anonymous.CleanupPolicy(values["cleanup"].Uint64)})
}

func terminalDeletionState(cleanup anonymous.CleanupPolicy) anonymous.State {
	if cleanup == anonymous.CleanupAnonymize {
		return anonymous.StateAnonymized
	}
	if cleanup == anonymous.CleanupRetain {
		return anonymous.StateRetained
	}
	return anonymous.StateDeleted
}

func disposalScope(w kernel.Work, p kernel.FeatureExecutionContributor, c identity.Command) (identity.CommandBinding, anonymous.SubjectSpec, error) {
	b, f, l, err := w.FeatureScope(p)
	spec, ok := c.Feature()
	if err != nil || !ok || spec.Binding != b || spec.Operation != deletionOperation() || f.Operation != spec.Operation || p.Descriptor() != creationOwner() || l.EventType != "anonymous.deleted.v1" || l.BeforeVersion != 1 || l.AfterVersion != 2 || b.RecordID != string(b.UserID) || string(b.ActorID) != string(b.UserID) {
		return identity.CommandBinding{}, anonymous.SubjectSpec{}, anonymous.ErrInvalidInput
	}
	s, err := deletionSubject(c)
	if err != nil {
		return identity.CommandBinding{}, anonymous.SubjectSpec{}, err
	}
	record, err := s.Record()
	return b, record, err
}

// StageDisposal terminalizes only this owner's exact active subject after the
// actual kernel's disposal in the same Work. Minimal lifecycle/command linkage
// is retained for non-resurrection and ambiguity recovery; no personal fields,
// credentials, bearer or application merge payloads are duplicated here.
// Every error must abort the complete command, including session effects.
func (r *Repository) StageDisposal(ctx context.Context, w kernel.Work, p kernel.FeatureExecutionContributor, c identity.Command) error {
	if ctx == nil || r == nil || r.pool == nil {
		return anonymous.ErrInvalidInput
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return err
	}
	b, expected, err := disposalScope(w, p, c)
	if err != nil {
		return err
	}
	user, err := w.AnonymousDisposal(p)
	if err != nil || user.ID != b.UserID || user.TenantID != b.TenantID {
		return identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, r.maximum)
	defer stop()
	rows, err := w.Query(bounded, subjectSelect(r.schema)+" WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE", string(b.TenantID), string(b.UserID))
	if err != nil {
		return err
	}
	subject, err := readSubject(rows)
	rows.Close()
	if err != nil {
		return err
	}
	actual, _ := subject.Record()
	if actual != expected {
		return identity.ConflictError{}
	}
	now, err := w.DatabaseTime(bounded)
	if err != nil {
		return err
	}
	if err := subject.RequireActive(b.TenantID, now); err != nil {
		return err
	}
	state := terminalDeletionState(expected.Cleanup)
	n, err := w.Exec(bounded, `UPDATE `+r.schema+`.subjects SET state=$3,version=2 WHERE tenant_id=$1 AND user_id=$2 AND state=1 AND version=1`, string(b.TenantID), string(b.UserID), int16(state))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return anonymous.ErrInvalidInput
	}
	n, err = w.Exec(bounded, `INSERT INTO `+r.schema+`.disposals(tenant_id,purpose,command_id,user_id,before_version,after_version,terminal_state,cleanup,created_at,expires_at) VALUES($1,$2,$3,$4,1,2,$5,$6,$7,$8)`, string(b.TenantID), b.OperationID, id, string(b.UserID), int16(state), int16(expected.Cleanup), expected.CreatedAt, expected.ExpiresAt)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// RequireDisposal verifies this owner's exact terminal state and original
// lifetime during the final read-only same-Work fence; no time is renewed.
func (r *Repository) RequireDisposal(ctx context.Context, w kernel.Work, p kernel.FeatureExecutionContributor, c identity.Command) error {
	if ctx == nil || r == nil || r.pool == nil {
		return anonymous.ErrInvalidInput
	}
	b, before, err := disposalScope(w, p, c)
	if err != nil {
		return err
	}
	bounded, stop := context.WithTimeout(ctx, r.maximum)
	defer stop()
	rows, err := w.Query(bounded, subjectSelect(r.schema)+" WHERE tenant_id=$1 AND user_id=$2 FOR SHARE", string(b.TenantID), string(b.UserID))
	if err != nil {
		return err
	}
	subject, err := readSubject(rows)
	rows.Close()
	if err != nil {
		return err
	}
	expected := before
	expected.State, expected.Version = terminalDeletionState(before.Cleanup), 2
	actual, _ := subject.Record()
	if actual != expected {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(bounded)
	if err != nil {
		return err
	}
	if now.Before(before.CreatedAt) || !now.Before(before.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}

// RecoverDisposal reads retained original metadata, never infers a successful
// deletion from absence or mutable user/session status. Only the sole existing
// coordinator can reconcile this participant with kernel/session/audit/outbox.
func (r *Repository) RecoverDisposal(ctx context.Context, w kernel.RecoveryWork, p kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || r == nil || r.pool == nil {
		return kernel.RecoveryUnknown, anonymous.ErrInvalidInput
	}
	b, f, l, err := w.FeatureScope(p)
	if err != nil || f.Operation != deletionOperation() || p.Descriptor() != creationOwner() || l.EventType != "anonymous.deleted.v1" || l.BeforeVersion != 1 || l.AfterVersion != 2 {
		return kernel.RecoveryUnknown, anonymous.ErrInvalidInput
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return kernel.RecoveryUnknown, anonymous.ErrInvalidInput
	}
	bounded, stop := context.WithTimeout(ctx, r.maximum)
	defer stop()
	rows, err := w.Query(bounded, `SELECT user_id,before_version::text,after_version::text,terminal_state,cleanup FROM `+r.schema+`.disposals WHERE tenant_id=$1 AND purpose=$2 AND command_id=$3`, string(b.TenantID), b.OperationID, id)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var user, before, after string
	var state, cleanup int16
	if err := rows.Scan(&user, &before, &after, &state, &cleanup); err != nil {
		return kernel.RecoveryUnknown, err
	}
	if rows.Next() || rows.Err() != nil || user != string(b.UserID) || before != strconv.FormatUint(l.BeforeVersion, 10) || after != strconv.FormatUint(l.AfterVersion, 10) || cleanup < 1 || cleanup > 3 || anonymous.State(state) != terminalDeletionState(anonymous.CleanupPolicy(cleanup)) {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}
