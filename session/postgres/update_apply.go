package postgres

import (
	"context"
	"crypto/sha256"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func (r *Repository) applyUpdate(ctx context.Context, w kernel.Work, native session.SessionCommand, until time.Time, intent [32]byte) (identity.FeatureReceipt, error) {
	if ctx == nil || r == nil || r.issueAdmission == nil || r.maximumDuration <= 0 {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	u, ok := native.Update()
	if !ok {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	source, _ := u.Source.Bindings()
	next, _ := u.Successor.Bindings()
	b, feature, transition, err := w.FeatureScope(r)
	if err != nil || b != u.Binding || feature.Operation != session.UpdateOperation() || transition.BeforeVersion != source.Version || transition.AfterVersion != next.Version {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, r.maximumDuration)
	defer stop()
	directory, credential, policy, err := sessionAdmissionBindings(IdentifierAdmissionConfig(*r.issueAdmission), u.Source, b, source.SessionID, source.Version)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = w.RequireActiveDirectoryAuthority(bounded, r, directory); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if _, err = w.RequireActiveCredential(bounded, r, credential); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = w.RequireActiveUserAuthorization(bounded, r, policy); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = r.requireIssueFamily(bounded, w, source, true); err != nil {
		return identity.FeatureReceipt{}, err
	}
	rows, err := w.Query(bounded, `SELECT record::text FROM `+r.schema+`.sessions WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3 AND version=$4::numeric AND state='active' FOR UPDATE`, string(b.TenantID), string(b.UserID), b.RecordID, strconv.FormatUint(source.Version, 10))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	var locked []byte
	err = readSessionAdmission(rows, &locked)
	rows.Close()
	if err != nil {
		return identity.FeatureReceipt{}, admissionError(bounded, err)
	}
	if err = RequireSession(bounded, w, Config{Schema: strings.Trim(r.schema, "\""), MaximumDuration: r.maximumDuration}, u.Source); err != nil {
		return identity.FeatureReceipt{}, err
	}
	now, err := w.DatabaseTime(bounded)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if !sessionReadTime(until) || !now.Before(until) || until.After(now.Add(20*time.Second)) || native.ValidateUpdateAt(now) != nil {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	before, _, err := encodeRecord(u.Source)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	after, _, err := encodeRecord(u.Successor)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	// Only the session version/vector changes. No digest trigger, refresh,
	// activity or expiry update is needed for non-authoritative display text.
	n, err := w.Exec(bounded, `UPDATE `+r.schema+`.sessions SET version=$1::numeric,record=$2::jsonb WHERE tenant_id=$3 AND user_id=$4 AND session_id=$5 AND version=$6::numeric AND state='active' AND record=$7::jsonb`, strconv.FormatUint(next.Version, 10), string(after), string(b.TenantID), string(b.UserID), b.RecordID, strconv.FormatUint(source.Version, 10), string(before))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	n, err = w.Exec(bounded, `INSERT INTO `+r.schema+`.session_labels(tenant_id,session_id,label) VALUES($1,$2,$3) ON CONFLICT(tenant_id,session_id) DO UPDATE SET label=EXCLUDED.label`, string(b.TenantID), b.RecordID, u.DeviceLabel)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	id, binding := updateEvidence(b, transition)
	sh, nh, lh := sha256.Sum256(before), sha256.Sum256(after), sha256.Sum256([]byte(u.DeviceLabel))
	n, err = w.Exec(bounded, `INSERT INTO `+r.schema+`.session_updates(tenant_id,command_id,purpose,user_id,session_id,family_id,before_version,after_version,binding_digest,source_digest,successor_digest,label_digest,intent_digest,source_record,successor_record) VALUES($1,$2,$3,$4,$5,$6,$7::numeric,$8::numeric,$9,$10,$11,$12,$13,$14::jsonb,$15::jsonb)`, string(b.TenantID), id, b.OperationID, string(b.UserID), b.RecordID, source.FamilyID, strconv.FormatUint(source.Version, 10), strconv.FormatUint(next.Version, 10), binding[:], sh[:], nh[:], lh[:], intent[:], string(before), string(after))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: session.UpdateOperation(), BeforeVersion: source.Version, AfterVersion: next.Version}, nil
}

func updateEvidence(b identity.CommandBinding, l kernel.LifecyclePlan) ([]byte, [32]byte) {
	id, base := revocationEvidence(b, l)
	return id, sha256.Sum256(append([]byte("identity-session-update-v1\x00"), base[:]...))
}
