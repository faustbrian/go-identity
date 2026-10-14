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

// Mutation owns no transaction. All current owners, original deadline, source
// CAS, digest retirement, successor and retained evidence share the coordinator
// Work; later audit/lifecycle failure rolls all of them back together.
func (r *Repository) applyRotation(ctx context.Context, w kernel.Work, native session.SessionCommand, until time.Time, intent [32]byte) (identity.FeatureReceipt, error) {
	if ctx == nil || r == nil || r.issueAdmission == nil || r.maximumDuration <= 0 {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	rotation, ok := native.Rotation()
	if !ok {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	source, _ := rotation.Source.Bindings()
	next, _ := rotation.Successor.Bindings()
	b, feature, transition, err := w.FeatureScope(r)
	if err != nil || b != rotation.Binding || feature.Operation != session.RotateOperation() || transition.BeforeVersion != source.Version || transition.AfterVersion != next.Version {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, r.maximumDuration)
	defer stop()
	directory, credential, policy, err := sessionAdmissionBindings(IdentifierAdmissionConfig(*r.issueAdmission), rotation.Source, b, source.SessionID, source.Version)
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
	// Family before session agrees with family-revocation lock order. Competing
	// rotations may share the family lock but cannot both hold the source CAS.
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
	if err = RequireSession(bounded, w, Config{Schema: strings.Trim(r.schema, "\""), MaximumDuration: r.maximumDuration}, rotation.Source); err != nil {
		return identity.FeatureReceipt{}, err
	}
	now, err := w.DatabaseTime(bounded)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if !sessionReadTime(until) || !now.Before(until) || until.After(now.Add(20*time.Second)) || native.ValidateRotationAt(now) != nil {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	before, _, err := encodeRecord(rotation.Source)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	after, expiry, err := encodeRecord(rotation.Successor)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	// This early denial is advisory only. The database's immutable token-claim
	// owner serializes every session writer, including older issuance binaries;
	// concurrent retirement cannot turn this absence into digest resurrection.
	rows, err = w.Query(bounded, `SELECT EXISTS(SELECT 1 FROM `+r.schema+`.retired_tokens WHERE tenant_id=$1 AND digest_version=$2 AND digest=$3)`, string(b.TenantID), int64(next.Lookup.KeyVersion), next.Lookup.Sum[:])
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	var retired bool
	if !rows.Next() || rows.Scan(&retired) != nil || rows.Next() || rows.Err() != nil {
		rows.Close()
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	rows.Close()
	if retired {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	n, err := w.Exec(bounded, `UPDATE `+r.schema+`.sessions SET version=$1::numeric,digest_version=$2,digest=$3,expires_at=$4,record=$5::jsonb WHERE tenant_id=$6 AND user_id=$7 AND session_id=$8 AND version=$9::numeric AND state='active' AND record=$10::jsonb`, strconv.FormatUint(next.Version, 10), int64(next.Lookup.KeyVersion), next.Lookup.Sum[:], expiry, string(after), string(b.TenantID), string(b.UserID), b.RecordID, strconv.FormatUint(source.Version, 10), string(before))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	id, binding := rotationEvidence(b, transition)
	sourceDigest, successorDigest := sha256.Sum256(before), sha256.Sum256(after)
	n, err = w.Exec(bounded, `INSERT INTO `+r.schema+`.session_rotations(tenant_id,command_id,purpose,user_id,session_id,family_id,before_version,after_version,binding_digest,source_digest,successor_digest,source_record,successor_record,intent_digest) VALUES($1,$2,$3,$4,$5,$6,$7::numeric,$8::numeric,$9,$10,$11,$12::jsonb,$13::jsonb,$14)`, string(b.TenantID), id, b.OperationID, string(b.UserID), b.RecordID, source.FamilyID, strconv.FormatUint(source.Version, 10), strconv.FormatUint(next.Version, 10), binding[:], sourceDigest[:], successorDigest[:], string(before), string(after), intent[:])
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	life, _ := rotation.Source.Lifetime(source.LastActivityAt)
	n, err = w.Exec(bounded, `INSERT INTO `+r.schema+`.retired_tokens(tenant_id,digest_version,digest,user_id,session_id,family_id,before_version,command_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7::numeric,$8,$9)`, string(b.TenantID), int64(source.Lookup.KeyVersion), source.Lookup.Sum[:], string(b.UserID), b.RecordID, source.FamilyID, strconv.FormatUint(source.Version, 10), id, life.AbsoluteExpiresAt.UTC().Format(storedTimeLayout))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: session.RotateOperation(), BeforeVersion: source.Version, AfterVersion: next.Version}, nil
}

func rotationEvidence(b identity.CommandBinding, l kernel.LifecyclePlan) ([]byte, [32]byte) {
	id, base := revocationEvidence(b, l)
	return id, sha256.Sum256(append([]byte("identity-session-rotation-v1\x00"), base[:]...))
}
