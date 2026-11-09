package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// OriginalOAuthLinkCounterKeys reads only original nonsecret key versions from
// this risk owner's existing primary charge. The native workflow must already
// authenticate the original flow/browser and pass its immutable binding/time.
// A result is not a charge, permission, proof, receipt or fresh validity evidence;
// the sole root owner must still match the complete original claim and plan.
// No row returns found=false. Existing NULL metadata, changed time/policy and
// missing retained keys deny rather than inventing historical aliases.
// MaximumDuration is 1ms..30s and never extends the caller deadline. Pool is
// borrowed and caller-owned. RetainCounterKeyVersions must be selected and its
// migration installed. Concurrent immutable calls perform bounded reads only.
func (r *Repository) OriginalOAuthLinkCounterKeys(ctx context.Context, pool *database.Pool, b identity.CommandBinding, at time.Time, maximumDuration time.Duration) ([]uint32, bool, error) {
	invalid := func() ([]uint32, bool, error) { return nil, false, risk.ErrInvalidCounterCommand }
	if ctx == nil || r == nil || !r.counterKeyVersions || r.counters == nil || pool == nil || pool.Raw() == nil || maximumDuration < time.Millisecond || maximumDuration > 30*time.Second || at.IsZero() || at != at.UTC() || !at.Equal(at.Truncate(time.Microsecond)) || b.PolicyVersion != r.policy || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || b.UserID == "" || b.OperationID != "identity.account.link-start" && b.OperationID != "identity.account.link-token" {
		return invalid()
	}
	if _, err := identity.ParseCommandID(string(b.CommandID)); err != nil {
		return invalid()
	}
	if _, err := identity.ParseIdentifierID(string(b.TenantID)); err != nil {
		return invalid()
	}
	ctx, stop := context.WithTimeout(ctx, maximumDuration)
	defer stop()
	raw, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	var policy string
	var prepared time.Time
	var count int
	var versions []int64
	err := pool.Raw().QueryRow(ctx, `SELECT policy_version::text,prepared_at,COALESCE(cardinality(key_versions),0),COALESCE(key_versions[1:4],'{}'::bigint[]) FROM `+r.schema+`.counter_charges WHERE command_id=$1 AND tenant_id=$2 AND operation=$3`, raw, string(b.TenantID), b.OperationID).Scan(&policy, &prepared, &count, &versions)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, false, identity.UnavailableError{}
	}
	if policy != strconv.FormatUint(r.policy, 10) || !prepared.Equal(at) || count < 1 || count > 4 || count != len(versions) {
		return invalid()
	}
	out := make([]uint32, len(versions))
	for i, v := range versions {
		if v < 1 || v > int64(^uint32(0)) || i > 0 && versions[i-1] <= v {
			return invalid()
		}
		out[i] = uint32(v)
	}
	if _, err := r.withRetainedCounterKeys(out); err != nil {
		return invalid()
	}
	return out, true, nil
}
