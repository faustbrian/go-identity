package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

type replayEvidence struct {
	user     identity.UserID
	family   string
	version  uint64
	lookup   session.TokenDigest
	rotation identity.CommandID
	source   [32]byte
	expires  time.Time
}

func (r *Repository) replayEvidenceSQL(locked bool) string {
	sql := `SELECT x.source_record::text,x.source_digest,t.user_id,t.session_id,t.family_id,t.before_version::text,t.command_id,t.expires_at::text,c.retired,x.user_id,x.session_id,x.family_id,x.before_version::text FROM ` + r.schema + `.retired_tokens t LEFT JOIN ` + r.schema + `.session_rotations x ON x.tenant_id=t.tenant_id AND x.command_id=t.command_id LEFT JOIN ` + r.schema + `.token_claims c ON c.tenant_id=t.tenant_id AND c.digest_version=t.digest_version AND c.digest=t.digest AND c.session_id=t.session_id WHERE t.tenant_id=$1 AND t.digest_version=$2 AND t.digest=$3`
	if locked {
		// Inner locking is separate from the nullable integrity joins: missing
		// retained infrastructure must be unavailable, not false absence.
		sql += ` FOR SHARE OF t`
	}
	return sql
}

func scanReplayEvidence(row rotationScanner, tenant identity.TenantID, lookup session.TokenDigest) (replayEvidence, error) {
	var out replayEvidence
	var record, hash, command []byte
	var user, id, family, before, expires, rotationUser, rotationID, rotationFamily, rotationBefore string
	var retired bool
	if err := row.Scan(&record, &hash, &user, &id, &family, &before, &command, &expires, &retired, &rotationUser, &rotationID, &rotationFamily, &rotationBefore); err != nil {
		return out, session.ErrUnavailable
	}
	source, err := decodeRecord(record)
	if err != nil {
		return out, session.ErrUnavailable
	}
	spec, _ := source.Bindings()
	canonical, _, err := encodeRecord(source)
	if err != nil {
		return out, session.ErrUnavailable
	}
	sum := sha256.Sum256(canonical)
	vector, _ := spec.Authority.Bindings()
	life, err := source.Lifetime(spec.LastActivityAt)
	if err != nil || spec.TenantID != tenant || string(spec.UserID) != user || spec.SessionID != id || spec.FamilyID != family || before != strconv.FormatUint(spec.Version, 10) || rotationUser != user || rotationID != id || rotationFamily != family || rotationBefore != before || !retired || spec.Lookup.KeyVersion != lookup.KeyVersion || subtle.ConstantTimeCompare(spec.Lookup.Sum[:], lookup.Sum[:]) != 1 || subtle.ConstantTimeCompare(hash, sum[:]) != 1 || expires != life.AbsoluteExpiresAt.UTC().Format(storedTimeLayout) || len(command) != 16 || vector.SessionFamily.Version == ^uint64(0) {
		return out, session.ErrUnavailable
	}
	rotation, err := identity.ParseCommandID(base64.RawURLEncoding.EncodeToString(command))
	if err != nil {
		return out, session.ErrUnavailable
	}
	return replayEvidence{user: spec.UserID, family: family, version: vector.SessionFamily.Version, lookup: lookup, rotation: rotation, source: sum, expires: life.AbsoluteExpiresAt}, nil
}

func (r *Repository) readReplayEvidence(ctx context.Context, tenant identity.TenantID, lookup session.TokenDigest) (replayEvidence, bool, error) {
	rows, err := r.pool.Raw().Query(ctx, r.replayEvidenceSQL(false), string(tenant), int64(lookup.KeyVersion), lookup.Sum[:])
	if err != nil {
		return replayEvidence{}, false, readError(ctx, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err = rows.Err(); err != nil {
			return replayEvidence{}, false, readError(ctx, err)
		}
		return replayEvidence{}, false, nil
	}
	out, err := scanReplayEvidence(rows, tenant, lookup)
	if err != nil || rows.Next() || rows.Err() != nil {
		return replayEvidence{}, false, session.ErrUnavailable
	}
	if ctx.Err() != nil {
		return replayEvidence{}, false, readError(ctx, ctx.Err())
	}
	return out, true, nil
}

func mapReplayEvidence(b identity.CommandBinding, proof replayEvidence) (identity.Command, error) {
	if b.UserID != proof.user || b.RecordID != proof.family {
		return identity.Command{}, session.ErrInvalidSessionCommand
	}
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: session.RevokeFamilyOperation(), Fields: []identity.FeatureField{
		{Name: "expected.version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: proof.version}},
		{Name: "replay.lookup.version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(proof.lookup.KeyVersion)}},
		{Name: "replay.lookup.digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: proof.lookup.Sum[:]}},
		{Name: "replay.rotation-command", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(proof.rotation)}},
		{Name: "replay.source.digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: proof.source[:]}},
		{Name: "replay.expires-at", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: proof.expires.UTC().Format(storedTimeLayout)}},
	}})
}

func nativeReplayEvidence(command identity.Command) (replayEvidence, error) {
	var out replayEvidence
	spec, ok := command.Feature()
	if !ok || spec.Operation != session.RevokeFamilyOperation() || len(spec.Fields) != 6 || spec.Binding.ActorKind != authorization.SubjectServiceAccount {
		return out, session.ErrInvalidSessionCommand
	}
	fields := make(map[string]identity.FeatureValue, 6)
	for _, field := range spec.Fields {
		fields[field.Name] = field.Value
	}
	valid := true
	take := func(name string, kind identity.FeatureKind) identity.FeatureValue {
		value, exists := fields[name]
		delete(fields, name)
		if !exists || value.Kind != kind {
			valid = false
		}
		return value
	}
	out.version = take("expected.version", identity.FeatureUint64).Uint64
	key := take("replay.lookup.version", identity.FeatureUint64).Uint64
	digest := take("replay.lookup.digest", identity.FeatureBytes).Bytes
	rotation := take("replay.rotation-command", identity.FeatureText).Text
	source := take("replay.source.digest", identity.FeatureBytes).Bytes
	expires := take("replay.expires-at", identity.FeatureText).Text
	var err error
	out.rotation, err = identity.ParseCommandID(rotation)
	if err != nil {
		valid = false
	}
	out.expires, err = time.Parse(storedTimeLayout, expires)
	if err != nil || !sessionReadTime(out.expires) || out.expires.UTC().Format(storedTimeLayout) != expires {
		valid = false
	}
	if !valid || len(fields) != 0 || out.version == 0 || out.version == ^uint64(0) || key == 0 || key > uint64(^uint32(0)) || len(digest) != 32 || len(source) != 32 {
		return replayEvidence{}, session.ErrInvalidSessionCommand
	}
	copy(out.lookup.Sum[:], digest)
	copy(out.source[:], source)
	if out.lookup.Sum == ([32]byte{}) || out.source == ([32]byte{}) {
		return replayEvidence{}, session.ErrInvalidSessionCommand
	}
	out.lookup.KeyVersion = uint32(key)
	out.user, out.family = spec.Binding.UserID, spec.Binding.RecordID
	return out, nil
}
