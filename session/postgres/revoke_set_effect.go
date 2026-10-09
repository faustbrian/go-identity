package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func (r *Repository) validateRevokeSetPlan(command identity.Command, p kernel.CommandPlan) error {
	if r == nil || r.issueAdmission == nil {
		return session.ErrInvalidSessionCommand
	}
	native, _, err := nativeRevokeSet(command)
	if err != nil {
		return err
	}
	set, _ := native.RevokeSet()
	spec, _ := set.Caller.Bindings()
	op, _ := command.Feature()
	if _, _, _, err = sessionAdmissionBindings(IdentifierAdmissionConfig(*r.issueAdmission), set.Caller, set.Binding, spec.SessionID, spec.Version); err != nil {
		return err
	}
	if p.Feature == nil || p.Feature.Contributor != r.Descriptor() || p.Feature.Operation != op.Operation || p.SubjectType != "session" || p.Capability != nil || p.Lifecycle == nil || p.Lifecycle.EventType != "session.set-revoked.v1" || p.Lifecycle.BeforeVersion != spec.Version || p.Lifecycle.AfterVersion != spec.Version+1 || len(p.Audits) != 1 {
		return session.ErrInvalidSessionCommand
	}
	a := p.Audits[0]
	if a.EventType != "identity.session.revoke" || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "standard" && a.RetentionClass != "protected" {
		return session.ErrInvalidSessionCommand
	}
	return nil
}

// Mutate the complete bounded set in the sole Work. The coordinator's existing
// tenant transaction mutex serializes all owned writers, including issuance;
// source/current owner locks remain until commit/abort. Target rows are
// locked in one bytewise order, never source-first followed by an unordered set.
// Active-state rows include expired or family-denied credentials; tombstoning
// them retains terminal history rather than allowing a later cleanup/refresh
// to resurrect them. The bound counts selected target rows, not pages.
func (r *Repository) applyRevokeSet(ctx context.Context, w kernel.Work, set session.RevokeSetCommandSpec, until time.Time) (identity.FeatureReceipt, error) {
	if ctx == nil || r == nil || r.issueAdmission == nil || r.maximumDuration <= 0 {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	b, feature, transition, err := w.FeatureScope(r)
	spec, e := set.Caller.Bindings()
	op := session.RevokeOtherOperation()
	if set.Binding.OperationID == session.RevokeAllOperation().OperationID {
		op = session.RevokeAllOperation()
	}
	if err != nil || e != nil || b != set.Binding || feature.Operation != op || transition.BeforeVersion != spec.Version || transition.AfterVersion != spec.Version+1 {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, r.maximumDuration)
	defer stop()
	directory, credential, policy, err := sessionAdmissionBindings(IdentifierAdmissionConfig(*r.issueAdmission), set.Caller, b, spec.SessionID, spec.Version)
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
	original, _, err := encodeRecord(set.Caller)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	// Work bounds each result to 256 rows/1MiB and admits scalar parameters
	// only. Validate small keyset chunks under the unchanged transaction lock;
	// do not buffer an unbounded result or pass a custom array codec to Work.
	const pageSize = 16
	sql := `SELECT s.record::text,s.state,f.state,f.version::text,s.expires_at,s.tenant_id,s.session_id,s.user_id,s.family_id,s.version::text,s.family_version::text,s.digest_version,s.digest FROM ` + r.schema + `.sessions s JOIN ` + r.schema + `.families f USING(tenant_id,family_id,user_id) WHERE s.tenant_id=$1 AND s.user_id=$2 AND s.state='active' AND s.session_id>$3 ORDER BY s.session_id LIMIT 16 FOR UPDATE OF s`
	var targetCount uint32
	foundSource := false
	cursor := ""
	for {
		rows, queryErr := w.Query(bounded, sql, string(b.TenantID), string(b.UserID), cursor)
		if queryErr != nil {
			return identity.FeatureReceipt{}, queryErr
		}
		pageCount := 0
		for rows.Next() {
			pageCount++
			row := primaryStoredRow{}
			if err = row.scan(rows); err != nil {
				break
			}
			stored, decodeErr := row.decode(b.TenantID, "", nil)
			if decodeErr != nil {
				err = decodeErr
				break
			}
			target, bindErr := stored.Session.Bindings()
			if bindErr != nil {
				err = bindErr
				break
			}
			if target.UserID != b.UserID || target.SessionID <= cursor || pageCount > pageSize {
				err = ErrInvalidRecord
				break
			}
			cursor = target.SessionID
			if target.SessionID == spec.SessionID {
				foundSource = true
				encoded, _, encodeErr := encodeRecord(stored.Session)
				if encodeErr != nil || !bytes.Equal(encoded, original) {
					err = identity.ConflictError{}
					break
				}
				if !set.IncludeCurrent {
					continue
				}
			}
			targetCount++
			if targetCount > set.MaximumSessions {
				err = identity.ConflictError{}
				break
			}
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if pageCount < pageSize {
			break
		}
	}
	if !foundSource {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err = RequireSession(bounded, w, Config{Schema: strings.Trim(r.schema, "\""), MaximumDuration: r.maximumDuration}, set.Caller); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = checkSetDeadline(bounded, w, set.Caller, until); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if targetCount > 0 {
		var n int64
		n, err = w.Exec(bounded, `UPDATE `+r.schema+`.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2 AND state='active' AND ($4::boolean OR session_id<>$3)`, string(b.TenantID), string(b.UserID), spec.SessionID, set.IncludeCurrent)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if n != int64(targetCount) {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
	}
	if !set.IncludeCurrent {
		record, err := revokeSetSuccessor(set.Caller)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		successor, _ := record.Bindings()
		payload, _, err := encodeRecord(record)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		n, err := w.Exec(bounded, `UPDATE `+r.schema+`.sessions SET version=$4::numeric,record=$5::jsonb WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3 AND state='active' AND version=$6::numeric AND record=$7::jsonb`, string(b.TenantID), string(b.UserID), spec.SessionID, strconv.FormatUint(successor.Version, 10), string(payload), strconv.FormatUint(spec.Version, 10), string(original))
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if n != 1 {
			return identity.FeatureReceipt{}, identity.ConflictError{}
		}
	}
	id, bindingDigest := revocationEvidence(b, transition)
	vector, _ := spec.Authority.Bindings()
	resultDigest := setResultDigest(b, transition.BeforeVersion, transition.AfterVersion, vector.User.Version, targetCount, set.IncludeCurrent)
	n, err := w.Exec(bounded, `INSERT INTO `+r.schema+`.set_revocations(tenant_id,command_id,purpose,user_id,source_id,before_version,after_version,subject_version,revoked_count,include_current,binding_digest,result_digest) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8::numeric,$9,$10,$11,$12)`, string(b.TenantID), id, b.OperationID, string(b.UserID), b.RecordID, strconv.FormatUint(spec.Version, 10), strconv.FormatUint(spec.Version+1, 10), strconv.FormatUint(vector.User.Version, 10), int64(targetCount), set.IncludeCurrent, bindingDigest[:], resultDigest[:])
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if err = checkSetDeadline(bounded, w, set.Caller, until); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: op, BeforeVersion: spec.Version, AfterVersion: spec.Version + 1}, nil
}

// Revoking other sessions advances only this source's session version. Keep
// historical authentication and its separately continued credential linkage;
// rebuilding from Bindings alone would silently restore the login-era version.
func revokeSetSuccessor(source session.Session) (session.Session, error) {
	spec, err := source.Bindings()
	if err != nil || spec.Version == ^uint64(0) {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	spec.Version++
	vector, err := spec.Authority.Bindings()
	if err != nil {
		return session.Session{}, err
	}
	vector.Session.Version = spec.Version
	spec.Authority, err = session.NewAuthoritySnapshot(vector)
	if err != nil {
		return session.Session{}, err
	}
	var csrf session.CSRFState
	if state, e := source.CSRFState().Bindings(); e == nil {
		state.Binding.SessionVersion = spec.Version
		csrf, err = session.NewCSRFState(state)
		if err != nil {
			return session.Session{}, err
		}
	}
	if continuation, ok := source.CredentialContinuation(); ok {
		return session.NewContinuedPasswordSession(spec, csrf, continuation)
	}
	if csrf != (session.CSRFState{}) {
		return session.NewSessionWithCSRF(spec, csrf)
	}
	return session.NewSession(spec)
}

func checkSetDeadline(ctx context.Context, w kernel.Work, caller session.Session, until time.Time) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	lifetime, err := caller.Lifetime(now)
	if err != nil || !lifetime.Fresh || !now.Before(until) || until.After(now.Add(20*time.Second)) {
		return identity.ForbiddenError{}
	}
	return nil
}

func setResultDigest(b identity.CommandBinding, before, after, subject uint64, count uint32, current bool) [32]byte {
	encoded, _ := json.Marshal(struct {
		Binding                identity.CommandBinding
		Before, After, Subject uint64
		Count                  uint32
		Current                bool
	}{b, before, after, subject, count, current})
	return sha256.Sum256(append([]byte("identity-session-set-result-v1\x00"), encoded...))
}

func (r *Repository) recoverRevokeSet(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, transition, err := w.FeatureScope(r)
	if err != nil || feature.Operation != session.RevokeOtherOperation() && feature.Operation != session.RevokeAllOperation() || transition.BeforeVersion == 0 || transition.BeforeVersion == ^uint64(0) || transition.AfterVersion != transition.BeforeVersion+1 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	id, bindingDigest := revocationEvidence(b, transition)
	rows, err := w.Query(ctx, `SELECT purpose,user_id,source_id,before_version::text,after_version::text,subject_version::text,revoked_count,include_current,binding_digest,result_digest FROM `+r.schema+`.set_revocations WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), id)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err = rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var purpose, user, source, before, after, subject string
	var count int64
	var current bool
	var binding, result []byte
	if err = rows.Scan(&purpose, &user, &source, &before, &after, &subject, &count, &current, &binding, &result); err != nil {
		return kernel.RecoveryUnknown, err
	}
	if rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	version, err := strconv.ParseUint(subject, 10, 64)
	if err != nil || version == 0 || subject != strconv.FormatUint(version, 10) || purpose != b.OperationID || user != string(b.UserID) || source != b.RecordID || before != strconv.FormatUint(transition.BeforeVersion, 10) || after != strconv.FormatUint(transition.AfterVersion, 10) || count < 0 || count > 100000 || current && count == 0 || feature.Operation == session.RevokeOtherOperation() && current || subtle.ConstantTimeCompare(binding, bindingDigest[:]) != 1 {
		return kernel.RecoveryUnknown, nil
	}
	expected := setResultDigest(b, transition.BeforeVersion, transition.AfterVersion, version, uint32(count), current)
	if subtle.ConstantTimeCompare(result, expected[:]) != 1 {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryCommitted, nil
}
