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

// This bounded portable native intent binds every mapped field (including the
// original deadline/transport). It complements, never replaces, the kernel's
// keyed command fingerprint and sole authoritative receipt.
func rotationIntentDigest(command identity.Command) ([32]byte, error) {
	if _, _, _, err := nativeRotationIntent(command); err != nil {
		return [32]byte{}, err
	}
	spec, _ := command.Feature()
	data, err := json.Marshal(spec)
	if err != nil || len(data) > 65536 {
		return [32]byte{}, session.ErrInvalidSessionCommand
	}
	return sha256.Sum256(append([]byte("identity-session-rotation-intent-v1\x00"), data...)), nil
}

type retainedRotation struct {
	source    session.Session
	successor session.Session
	intent    [32]byte
}
type rotationScanner interface{ Scan(...any) error }

func (r *Repository) rotationSelect() string {
	return `SELECT x.purpose,x.user_id,x.session_id,x.family_id,x.before_version::text,x.after_version::text,x.binding_digest,x.source_digest,x.successor_digest,x.intent_digest,x.source_record::text,x.successor_record::text,t.digest_version,t.digest,t.user_id,t.session_id,t.family_id,t.before_version::text,t.expires_at::text,c.retired FROM ` + r.schema + `.session_rotations x LEFT JOIN ` + r.schema + `.retired_tokens t ON t.tenant_id=x.tenant_id AND t.command_id=x.command_id LEFT JOIN ` + r.schema + `.token_claims c ON c.tenant_id=t.tenant_id AND c.digest_version=t.digest_version AND c.digest=t.digest AND c.session_id=t.session_id WHERE x.tenant_id=$1 AND x.command_id=$2`
}

func scanRotation(row rotationScanner, b identity.CommandBinding, l kernel.LifecyclePlan) (retainedRotation, error) {
	var out retainedRotation
	var purpose, user, id, family, before, after, retiredUser, retiredID, retiredFamily, retiredBefore, expiry string
	var binding, sourceHash, successorHash, intent, sourceBytes, successorBytes, digest []byte
	var version int64
	var retired bool
	if err := row.Scan(&purpose, &user, &id, &family, &before, &after, &binding, &sourceHash, &successorHash, &intent, &sourceBytes, &successorBytes, &version, &digest, &retiredUser, &retiredID, &retiredFamily, &retiredBefore, &expiry, &retired); err != nil {
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
	native, err := session.NewRotateCommand(b, source, successor)
	if err != nil {
		return out, err
	}
	rotation, _ := native.Rotation()
	old, _ := rotation.Source.Bindings()
	next, _ := rotation.Successor.Bindings()
	_, expected := rotationEvidence(b, l)
	canonicalSource, _, _ := encodeRecord(source)
	canonicalNext, _, _ := encodeRecord(successor)
	sh, nh := sha256.Sum256(canonicalSource), sha256.Sum256(canonicalNext)
	life, err := source.Lifetime(old.LastActivityAt)
	if err != nil {
		return out, err
	}
	if purpose != b.OperationID || user != string(b.UserID) || id != b.RecordID || family != old.FamilyID || before != strconv.FormatUint(l.BeforeVersion, 10) || after != strconv.FormatUint(l.AfterVersion, 10) || old.Version != l.BeforeVersion || next.Version != l.AfterVersion || subtle.ConstantTimeCompare(binding, expected[:]) != 1 || subtle.ConstantTimeCompare(sourceHash, sh[:]) != 1 || subtle.ConstantTimeCompare(successorHash, nh[:]) != 1 || len(intent) != 32 || bytes.Equal(intent, make([]byte, 32)) || version != int64(old.Lookup.KeyVersion) || !bytes.Equal(digest, old.Lookup.Sum[:]) || retiredUser != user || retiredID != id || retiredFamily != family || retiredBefore != before || expiry != life.AbsoluteExpiresAt.UTC().Format(storedTimeLayout) || !retired {
		return out, session.ErrUnavailable
	}
	copy(out.intent[:], intent)
	out.source = source
	out.successor = successor
	return out, nil
}

func (r *Repository) readRotation(ctx context.Context, b identity.CommandBinding, l kernel.LifecyclePlan) (retainedRotation, error) {
	id, _ := rotationEvidence(b, l)
	rows, err := r.pool.Raw().Query(ctx, r.rotationSelect(), string(b.TenantID), id)
	if err != nil {
		return retainedRotation{}, readError(ctx, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return retainedRotation{}, session.ErrUnavailable
	}
	out, err := scanRotation(rows, b, l)
	if err != nil {
		return retainedRotation{}, readError(ctx, err)
	}
	if rows.Next() || rows.Err() != nil {
		return retainedRotation{}, session.ErrUnavailable
	}
	if ctx.Err() != nil {
		return retainedRotation{}, readError(ctx, ctx.Err())
	}
	return out, nil
}

func (r *Repository) recoverRotation(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, feature, l, err := w.FeatureScope(r)
	if err != nil || feature.Operation != session.RotateOperation() || l.BeforeVersion == 0 || l.BeforeVersion == ^uint64(0) || l.AfterVersion != l.BeforeVersion+1 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	id, _ := rotationEvidence(b, l)
	rows, err := w.Query(ctx, r.rotationSelect(), string(b.TenantID), id)
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
	_, err = scanRotation(rows, b, l)
	if err != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, session.ErrUnavailable
	}
	return kernel.RecoveryCommitted, nil
}
