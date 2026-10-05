package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgtype"
)

// This policy is private until the native authorized identifier owner exists.
// Keys are immutable during a call, with at most 16 retained versions. Stored
// cooldown expiry is conserved across policy/key changes, never recomputed.
type identifierMutationPolicy struct {
	currentKeyVersion uint32
	keys              map[uint32][32]byte
	reuseCooldown     time.Duration
}

func (identifierMutationPolicy) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.identifierMutationPolicy(redacted)"))
}
func (p identifierMutationPolicy) valid() bool {
	if p.currentKeyVersion == 0 || len(p.keys) == 0 || len(p.keys) > 16 || p.reuseCooldown < 0 || p.reuseCooldown > 365*24*time.Hour || p.reuseCooldown%time.Microsecond != 0 {
		return false
	}
	if _, ok := p.keys[p.currentKeyVersion]; !ok {
		return false
	}
	for version, key := range p.keys {
		if version == 0 || key == ([32]byte{}) {
			return false
		}
	}
	return true
}
func identifierReuseDigest(key [32]byte, tenant identity.TenantID, kind identity.IdentifierKind, value string) [32]byte {
	h := hmac.New(sha256.New, key[:])
	_, _ = h.Write([]byte("identity-identifier-reuse-v1\x00"))
	for _, field := range []string{string(tenant), string(kind), value} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(field))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

type identifierWorkResult struct {
	user    identity.User
	receipt identity.IdentifierReceipt
	// These are invocation completion facts, not current session or policy
	// authority. Only this storage path and the coordinator set them.
	proofConsumed, proofFinalized bool
}

// applyIdentifierMutation is provisional native storage, deliberately private.
// It grants no current policy/session/challenge/final-access authority. It
// consumes the enlisted proof provisionally but does not stage audit/lifecycle
// or close the transaction. Public Begin
// remains disabled for this profile until those owners and Commit are complete.
func (r *Repository) applyIdentifierMutation(ctx context.Context, w Work, command identity.Command, policy identifierMutationPolicy) (identity.IdentifierMutation, error) {
	zero := identity.IdentifierMutation{}
	if err := w.usable(); err != nil {
		return zero, err
	}
	fail := func(err error) (identity.IdentifierMutation, error) { return zero, w.fail(w.state.ctx, err) }
	if ctx == nil || r == nil || r.pool == nil || !policy.valid() || w.state.execution == nil || w.state.identifier != nil || w.state.creation != nil || w.state.profile != nil || w.state.update != nil || w.state.status != nil || w.state.featureReceipt != nil {
		return fail(invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return zero, w.fail(ctx, err)
	}
	c := w.state.execution.coordinator
	p := w.state.execution.reservation
	if !c.owns(w) || p.plan.belongsTo(c.registry) != nil || p.plan.capability == nil || w.state.generation == 0 || p.plan.binding != w.state.binding {
		return fail(invalidWork())
	}
	enlisted := false
	for _, e := range p.plan.contributors {
		if e.descriptor.Owner == "identity/postgres" && e.contributor == r {
			enlisted = true
		}
	}
	spec, ok := command.ChangeIdentifier()
	if !enlisted || !ok || spec.Binding != w.state.binding {
		return fail(invalidWork())
	}
	q, err := prepareClaim(command, c.keys.retained[c.keys.current])
	if err != nil || !bytes.Equal(q.canonical, p.request.canonical) {
		return fail(identity.ConflictError{})
	}
	if p.plan.identifierAdmission != nil {
		if err = c.runIdentifierAdmission(ctx, w, command, false); err != nil {
			return zero, err
		}
	}
	state, now, err := lockIdentifierPartition(ctx, w, spec.Change)
	if err != nil {
		return zero, err
	}
	mutation, err := identity.ApplyIdentifierChange(state, spec.Change, now)
	if err != nil {
		return fail(err)
	}
	if spec.Change.Action == identity.IdentifierAttach || spec.Change.Action == identity.IdentifierReplace {
		if err = checkIdentifierReuse(ctx, w, spec.Change, policy, now); err != nil {
			return zero, err
		}
	}
	// Domain and proof effects share this Work. Failure after this phase must
	// roll back consumption as well as the identifier/retirement prefix.
	if err = c.runCapabilityExecution(ctx, w, false); err != nil {
		return zero, err
	}
	if mutation.Retired != nil {
		retired := mutation.Retired
		v := mutation.RetiredVerification
		digest := identifierReuseDigest(policy.keys[policy.currentKeyVersion], spec.Change.TenantID, retired.Kind, retired.CanonicalValue)
		until := now.Add(policy.reuseCooldown)
		if !postgresExactTime(until) {
			return fail(invalidWork())
		}
		n, e := w.Exec(ctx, `INSERT INTO identity.identifier_retirements(tenant_id,user_id,identifier_id,kind,record_version,verification_version,removed,command_id,key_version,value_digest,retired_at,reuse_until) VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,$7,$8,$9,$10,$11,$12)`, string(spec.Change.TenantID), string(spec.Change.UserID), string(retired.ID), string(retired.Kind), retired.Version, v.Version, spec.Change.Action == identity.IdentifierRemove, string(spec.Binding.CommandID), policy.currentKeyVersion, digest[:], now, until)
		if e != nil {
			return zero, e
		}
		if n != 1 {
			return fail(identity.ConflictError{})
		}
	}
	// Demote first: the partial unique index is immediate, not deferrable.
	for _, old := range state.Identifiers {
		index := slices.IndexFunc(mutation.State.Identifiers, func(i identity.Identifier) bool { return i.ID == old.ID })
		if old.Primary && index >= 0 && !mutation.State.Identifiers[index].Primary {
			n, e := w.Exec(ctx, `UPDATE identity.identifiers SET is_primary=false WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=$4::numeric`, string(spec.Change.TenantID), string(spec.Change.UserID), string(old.ID), old.Version)
			if e != nil {
				return zero, e
			}
			if n != 1 {
				return fail(identity.ConflictError{})
			}
		}
	}
	if spec.Change.Action == identity.IdentifierRemove {
		n, e := w.Exec(ctx, `DELETE FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=$4::numeric AND verification_version=$5::numeric`, string(spec.Change.TenantID), string(spec.Change.UserID), string(spec.Change.ID), spec.Change.ExpectedIdentifierVersion, spec.Change.ExpectedVerificationVersion)
		if e != nil {
			return zero, e
		}
		if n != 1 {
			return fail(identity.ConflictError{})
		}
	}
	for index, next := range mutation.State.Identifiers {
		vi := mutation.State.Verifications[index]
		oldIndex := slices.IndexFunc(state.Identifiers, func(i identity.Identifier) bool { return i.ID == next.ID })
		if oldIndex >= 0 && state.Identifiers[oldIndex] == next && state.Verifications[oldIndex] == vi {
			continue
		}
		var at any
		if !vi.VerifiedAt.IsZero() {
			at = vi.VerifiedAt
		}
		args := []any{string(spec.Change.TenantID), string(spec.Change.UserID), string(next.ID), string(next.Kind), next.CanonicalValue, next.DisplayValue, next.Verified, next.Primary, next.Version, int16(vi.State), vi.Version, at}
		sql := `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,display_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::numeric,$10,$11::numeric,$12)`
		if oldIndex >= 0 {
			sql = `UPDATE identity.identifiers SET kind=$4,canonical_value=$5,display_value=$6,verified=$7,is_primary=$8,version=$9::numeric,verification_state=$10,verification_version=$11::numeric,verified_at=$12 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=$13::numeric AND verification_version=$14::numeric`
			args = append(args, state.Identifiers[oldIndex].Version, state.Verifications[oldIndex].Version)
		}
		n, e := w.Exec(ctx, sql, args...)
		if e != nil {
			return zero, e
		}
		if n != 1 {
			return fail(identity.ConflictError{})
		}
	}
	n, err := w.Exec(ctx, `UPDATE identity.users SET version=$4::numeric,identifier_version=$5::numeric WHERE tenant_id=$1 AND user_id=$2 AND status='active' AND version=$3::numeric AND identifier_version=$6::numeric`, string(spec.Change.TenantID), string(spec.Change.UserID), state.User.Version, mutation.State.User.Version, mutation.State.AuthorityVersion, state.AuthorityVersion)
	if err != nil {
		return zero, err
	}
	if n != 1 {
		return fail(identity.ConflictError{})
	}
	if err = ctx.Err(); err != nil {
		return zero, w.fail(ctx, err)
	}
	digest, _ := identity.IdentifierIntentDigest(spec.Change)
	w.state.identifier = &identifierWorkResult{user: mutation.State.User, receipt: identity.IdentifierReceipt{IdentifierID: spec.Change.ID, Action: spec.Change.Action, ExpectedAuthorityVersion: state.AuthorityVersion, AuthorityVersion: mutation.State.AuthorityVersion, IntentDigest: digest}, proofConsumed: true}
	return mutation, nil
}

// Finalization follows every provisional domain/audit/outbox effect and must
// succeed before terminal receipt persistence. It never permits a missing apply
// or retries a failed phase. The native participant rechecks primary expiry.
func (c *Coordinator) finalizeIdentifierCapability(w Work) error {
	if !c.owns(w) {
		return invalidWork()
	}
	if err := w.usable(); err != nil {
		return err
	}
	if w.state.identifier == nil {
		return nil
	}
	owned := w.state.identifier
	if !owned.proofConsumed || owned.proofFinalized {
		return w.fail(w.state.ctx, invalidWork())
	}
	if w.state.execution.reservation.plan.identifierAdmission != nil {
		progress := w.state.identifierAdmission
		if progress == nil {
			return w.fail(w.state.ctx, invalidWork())
		}
		if err := c.runIdentifierAdmission(w.state.ctx, w, progress.command, true); err != nil {
			return err
		}
	}
	if err := c.runCapabilityExecution(w.state.ctx, w, true); err != nil {
		return err
	}
	owned.proofFinalized = true
	return nil
}

func lockIdentifierPartition(ctx context.Context, w Work, change identity.IdentifierChange) (identity.IdentifierState, time.Time, error) {
	fail := func(err error) (identity.IdentifierState, time.Time, error) {
		return identity.IdentifierState{}, time.Time{}, w.fail(ctx, err)
	}
	rows, err := w.Query(ctx, `SELECT tenant_id,user_id,status,version::text,identifier_version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, string(change.TenantID), string(change.UserID))
	if err != nil {
		return identity.IdentifierState{}, time.Time{}, err
	}
	var userRow identifierStorageRow
	if !rows.Next() {
		e := rows.Err()
		rows.Close()
		if e != nil {
			return fail(e)
		}
		return fail(identity.ForbiddenError{})
	}
	err = rows.Scan(&userRow.tenant, &userRow.user, &userRow.status, &userRow.userVersion, &userRow.authority)
	if err != nil {
		rows.Close()
		return fail(err)
	}
	if rows.Next() {
		rows.Close()
		return fail(identity.UnavailableError{})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return fail(err)
	}
	rows, err = w.Query(ctx, `SELECT identifier_id,kind,canonical_value,display_value,verified,is_primary,version::text,verification_state,verification_version::text,verified_at FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 ORDER BY identifier_id LIMIT 129 FOR UPDATE`, string(change.TenantID), string(change.UserID))
	if err != nil {
		return fail(err)
	}
	raw := make([]identifierStorageRow, 0, 8)
	for rows.Next() {
		row := userRow
		var id, kind, canonical, display, version, vversion string
		var verified, primary bool
		var state int16
		var at *time.Time
		if err = rows.Scan(&id, &kind, &canonical, &display, &verified, &primary, &version, &state, &vversion, &at); err != nil {
			rows.Close()
			return fail(err)
		}
		if len(raw) == 128 {
			rows.Close()
			return fail(identity.UnavailableError{})
		}
		row.id = pgtype.Text{String: id, Valid: true}
		row.kind = pgtype.Text{String: kind, Valid: true}
		row.canonical = pgtype.Text{String: canonical, Valid: true}
		row.display = pgtype.Text{String: display, Valid: true}
		row.version = pgtype.Text{String: version, Valid: true}
		row.verificationVersion = pgtype.Text{String: vversion, Valid: true}
		row.verified = pgtype.Bool{Bool: verified, Valid: true}
		row.primary = pgtype.Bool{Bool: primary, Valid: true}
		row.verificationState = pgtype.Int2{Int16: state, Valid: true}
		if at != nil {
			row.verifiedAt = pgtype.Timestamptz{Time: *at, Valid: true}
		}
		raw = append(raw, row)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return fail(err)
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return fail(err)
	}
	userRow.now = now
	q := identity.IdentifierQuery{TenantID: change.TenantID, UserID: change.UserID, MaximumIdentifiers: 128}
	user, epoch, _, _, _, err := decodeIdentifierRow(q, userRow)
	if err != nil {
		return fail(err)
	}
	result := identity.IdentifierState{User: user, AuthorityVersion: epoch}
	for _, row := range raw {
		row.now = now
		_, _, i, v, _, e := decodeIdentifierRow(q, row)
		if e != nil {
			return fail(e)
		}
		result.Identifiers = append(result.Identifiers, i)
		result.Verifications = append(result.Verifications, v)
	}
	return result, now, nil
}

func checkIdentifierReuse(ctx context.Context, w Work, c identity.IdentifierChange, p identifierMutationPolicy, now time.Time) error {
	check := func(sql string, args ...any) (bool, error) {
		rows, err := w.Query(ctx, sql, args...)
		if err != nil {
			return false, err
		}
		defer rows.Close()
		var exists bool
		if !rows.Next() {
			if e := rows.Err(); e != nil {
				return false, e
			}
			return false, w.fail(ctx, identity.UnavailableError{})
		}
		if err = rows.Scan(&exists); err != nil {
			return false, err
		}
		if rows.Next() {
			return false, w.fail(ctx, identity.UnavailableError{})
		}
		if err = rows.Err(); err != nil {
			return false, err
		}
		return exists, nil
	}
	occupied, err := check(`SELECT EXISTS(SELECT 1 FROM identity.identifiers WHERE tenant_id=$1 AND kind=$2 AND canonical_value=$3 AND (user_id<>$4 OR identifier_id<>$5))`, string(c.TenantID), string(c.Kind), c.CanonicalValue, string(c.UserID), string(c.ID))
	if err != nil {
		return err
	}
	if occupied {
		return w.fail(ctx, identity.ConflictError{})
	}
	if c.Action == identity.IdentifierAttach {
		// Identifier IDs are tenant-wide, independently of canonical kind/value
		// uniqueness. The dominating tenant lock makes both checks stable.
		reserved, err := check(`SELECT EXISTS(SELECT 1 FROM identity.identifiers WHERE tenant_id=$1 AND identifier_id=$2) OR EXISTS(SELECT 1 FROM identity.identifier_retirements WHERE tenant_id=$1 AND identifier_id=$2)`, string(c.TenantID), string(c.ID))
		if err != nil {
			return err
		}
		if reserved {
			return w.fail(ctx, identity.ConflictError{})
		}
	}
	rows, err := w.Query(ctx, `SELECT DISTINCT key_version FROM identity.identifier_retirements WHERE tenant_id=$1 AND kind=$2 AND reuse_until>$3 LIMIT 17`, string(c.TenantID), string(c.Kind), now)
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var version uint32
		if err = rows.Scan(&version); err != nil {
			rows.Close()
			return err
		}
		count++
		if _, ok := p.keys[version]; !ok || count > 16 {
			rows.Close()
			return w.fail(ctx, identity.UnavailableError{})
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	versions := make([]uint32, 0, len(p.keys))
	for v := range p.keys {
		versions = append(versions, v)
	}
	slices.Sort(versions)
	for _, version := range versions {
		digest := identifierReuseDigest(p.keys[version], c.TenantID, c.Kind, c.CanonicalValue)
		blocked, err := check(`SELECT EXISTS(SELECT 1 FROM identity.identifier_retirements WHERE tenant_id=$1 AND kind=$2 AND key_version=$3 AND value_digest=$4 AND reuse_until>$5)`, string(c.TenantID), string(c.Kind), version, digest[:], now)
		if err != nil {
			return err
		}
		if blocked {
			return w.fail(ctx, identity.ConflictError{})
		}
	}
	return nil
}
