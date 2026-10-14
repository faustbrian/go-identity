package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func updateIntentDigest(command identity.Command) ([32]byte, error) {
	if _, _, _, err := nativeUpdateIntent(command); err != nil {
		return [32]byte{}, err
	}
	p, _ := command.Feature()
	data, err := json.Marshal(p)
	if err != nil || len(data) > 65536 {
		return [32]byte{}, session.ErrInvalidSessionCommand
	}
	return sha256.Sum256(append([]byte("identity-session-update-intent-v1\x00"), data...)), nil
}

type retainedUpdate struct {
	source, successor session.Session
	intent, label     [32]byte
}

func (r *Repository) updateSelect() string {
	return `SELECT purpose,user_id,session_id,family_id,before_version::text,after_version::text,binding_digest,source_digest,successor_digest,intent_digest,label_digest,source_record::text,successor_record::text FROM ` + r.schema + `.session_updates WHERE tenant_id=$1 AND command_id=$2`
}

func scanUpdate(row rotationScanner, b identity.CommandBinding, l kernel.LifecyclePlan) (retainedUpdate, error) {
	var out retainedUpdate
	var purpose, user, id, family, before, after string
	var binding, sh, nh, intent, label, sourceBytes, successorBytes []byte
	if err := row.Scan(&purpose, &user, &id, &family, &before, &after, &binding, &sh, &nh, &intent, &label, &sourceBytes, &successorBytes); err != nil {
		return out, err
	}
	source, err := decodeRecord(sourceBytes)
	if err != nil {
		return out, err
	}
	successor, err := decodeRecord(successorBytes)
	if err != nil {
		return out, err
	}
	// A digest is sufficient for historical label intent; label plaintext is
	// not duplicated in terminal evidence or needed for outcome-only recovery.
	native, err := session.NewUpdateCommand(b, source, "")
	if err != nil {
		return out, err
	}
	u, _ := native.Update()
	expectedNext, _, _ := encodeRecord(u.Successor)
	canonicalSource, _, _ := encodeRecord(source)
	canonicalNext, _, _ := encodeRecord(successor)
	old, _ := source.Bindings()
	next, _ := successor.Bindings()
	_, expected := updateEvidence(b, l)
	sourceHash, nextHash := sha256.Sum256(canonicalSource), sha256.Sum256(canonicalNext)
	if purpose != b.OperationID || user != string(b.UserID) || id != b.RecordID || family != old.FamilyID || before != strconv.FormatUint(l.BeforeVersion, 10) || after != strconv.FormatUint(l.AfterVersion, 10) || old.Version != l.BeforeVersion || next.Version != l.AfterVersion || !bytes.Equal(canonicalNext, expectedNext) || subtle.ConstantTimeCompare(binding, expected[:]) != 1 || subtle.ConstantTimeCompare(sh, sourceHash[:]) != 1 || subtle.ConstantTimeCompare(nh, nextHash[:]) != 1 || len(intent) != 32 || bytes.Equal(intent, make([]byte, 32)) || len(label) != 32 || bytes.Equal(label, make([]byte, 32)) {
		return out, session.ErrUnavailable
	}
	out.source, out.successor = source, successor
	copy(out.intent[:], intent)
	copy(out.label[:], label)
	return out, nil
}

func (r *Repository) readUpdate(ctx context.Context, b identity.CommandBinding, l kernel.LifecyclePlan) (retainedUpdate, error) {
	id, _ := updateEvidence(b, l)
	rows, err := r.pool.Raw().Query(ctx, r.updateSelect(), string(b.TenantID), id)
	if err != nil {
		return retainedUpdate{}, readError(ctx, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return retainedUpdate{}, readError(ctx, rows.Err())
		}
		return retainedUpdate{}, session.ErrUnavailable
	}
	out, err := scanUpdate(rows, b, l)
	if err != nil {
		return retainedUpdate{}, readError(ctx, err)
	}
	if rows.Next() || rows.Err() != nil {
		return retainedUpdate{}, session.ErrUnavailable
	}
	if ctx.Err() != nil {
		return retainedUpdate{}, readError(ctx, ctx.Err())
	}
	return out, nil
}

func (r *Repository) recoverUpdate(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, f, l, err := w.FeatureScope(r)
	if err != nil || f.Operation != session.UpdateOperation() || l.BeforeVersion == 0 || l.BeforeVersion == ^uint64(0) || l.AfterVersion != l.BeforeVersion+1 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	id, _ := updateEvidence(b, l)
	rows, err := w.Query(ctx, r.updateSelect(), string(b.TenantID), id)
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
	if _, err = scanUpdate(rows, b, l); err != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, session.ErrUnavailable
	}
	return kernel.RecoveryCommitted, nil
}
