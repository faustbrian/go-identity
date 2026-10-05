package postgres

import (
	"context"
	"fmt"
	"io"
	"math"
	"strconv"

	identity "github.com/faustbrian/go-identity"
)

// privacyAllocation is provisional same-Work metadata, not a committed job or
// snapshot/cut authority. The protected owner must still verify current native
// session/proof/policy, capture all cuts and persist admission/audit/lifecycle
// before the existing coordinator can commit. It cannot be exposed as queued.
type privacyAllocation struct {
	exportID                                        identity.PrivacyExportJobID
	identityVersion, authorityVersion, privacyEpoch uint64
	requestedAtMicroseconds                         int64
}

func (privacyAllocation) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "postgres.privacyAllocation(redacted)")
}

// allocatePrivacyExport is private native storage inside the sole Work. It
// locks the exact user aggregate before primary time, checks every expected
// version and destructive disposition, generates the export ID and advances
// only privacy epoch. It never opens/closes a transaction or caches authority.
// Failure poisons Work even if a future caller ignores the error. Public
// privacy execution remains closed until the complete protected owner exists.
func allocatePrivacyExport(ctx context.Context, w Work, c identity.PrivacyExportRequestCommand) (privacyAllocation, error) {
	zero := privacyAllocation{}
	if err := w.usable(); err != nil {
		return zero, err
	}
	fail := func(err error) (privacyAllocation, error) { return zero, w.fail(w.state.ctx, err) }
	if ctx == nil || c.Binding != w.state.binding {
		return fail(invalidWork())
	}
	if _, err := identity.PrivacyExportIntentDigest(c); err != nil {
		return fail(invalidWork())
	}
	rows, err := w.Query(ctx, `SELECT tenant_id,user_id,status,version::text,authority_version::text,privacy_epoch::text,privacy_disposition
 FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, string(c.Binding.TenantID), string(c.Binding.UserID))
	if err != nil {
		return fail(err)
	}
	var tenant, user, status, version, authority, epoch, disposition string
	if !rows.Next() {
		err := rows.Err()
		rows.Close()
		if err != nil {
			return zero, err
		}
		return fail(identity.ForbiddenError{})
	}
	if err = rows.Scan(&tenant, &user, &status, &version, &authority, &epoch, &disposition); err != nil {
		rows.Close()
		return zero, err
	}
	if rows.Next() {
		rows.Close()
		return fail(identity.UnavailableError{})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return zero, err
	}
	parse := func(raw string) (uint64, bool) {
		n, e := strconv.ParseUint(raw, 10, 64)
		return n, e == nil && n > 0 && strconv.FormatUint(n, 10) == raw
	}
	v, vok := parse(version)
	a, aok := parse(authority)
	p, pok := parse(epoch)
	current := identity.User{ID: identity.UserID(user), TenantID: identity.TenantID(tenant), Status: identity.Status(status), Version: v}
	if !vok || !aok || !pok || current.Validate(c.Binding.TenantID) != nil || current.ID != c.Binding.UserID || disposition != "idle" && disposition != "anonymization-pending" && disposition != "deletion-pending" {
		return fail(identity.UnavailableError{})
	}
	if current.Status != identity.StatusActive || disposition != "idle" {
		return fail(identity.ForbiddenError{})
	}
	if v != c.ExpectedIdentityVersion || a != c.ExpectedAuthorityVersion || p != c.ExpectedPrivacyEpoch || p == math.MaxUint64 {
		return fail(identity.ConflictError{})
	}
	// No transaction-start timestamp or pre-lock wall time may stand in for the
	// primary observation after a concurrent lifecycle writer releases its lock.
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return zero, err
	}
	id, err := identity.NewPrivacyExportJobID()
	if err != nil {
		return fail(identity.UnavailableError{})
	}
	changed, err := w.Exec(ctx, `UPDATE identity.users SET privacy_epoch=privacy_epoch+1
 WHERE tenant_id=$1 AND user_id=$2 AND privacy_epoch::text=$3 AND privacy_disposition='idle'`, string(c.Binding.TenantID), string(c.Binding.UserID), epoch)
	if err != nil {
		return zero, err
	}
	if changed != 1 {
		return fail(identity.ConflictError{})
	}
	return privacyAllocation{exportID: id, identityVersion: v, authorityVersion: a, privacyEpoch: p + 1, requestedAtMicroseconds: now.UnixMicro()}, nil
}
