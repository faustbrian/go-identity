package postgres

import (
	"context"
	"slices"
	"time"
)

// UsernameAvailable observes canonical occupancy and live keyed cooldowns on
// the primary. It is advisory only: it takes no reservation/lock, and another
// signup or rename may win immediately. The workflow must enforce trusted
// tenant/network rate admission before exposing the result. This low-level
// reader grants no authentication, authorization or reusable validity lease.
//
// UserID must be absent: availability cannot exclude a caller-selected owner.
// Existing names block regardless of user status or historical comparison
// binding, matching the canonical unique index. Missing retained keys, missing
// schema and cancellation deny rather than promise availability. The earlier
// caller deadline bounds the borrowed repository budget; no resource is retained.
func (d *UsernameRenameDomain) UsernameAvailable(ctx context.Context, q UsernameQuery) (bool, error) {
	if ctx == nil || d == nil || d.repository == nil || d.repository.pool == nil || d.repository.pool.Raw() == nil || d.repository.maximumDuration <= 0 || d.repository.maximumDuration > time.Minute || !d.reuse.valid() || q.Validate() != nil || q.UserID != "" || q.NormalizationProfile != d.profile || q.NormalizationVersion != d.version {
		return false, invalidUsernameLookup()
	}
	bounded, cancel := context.WithTimeout(ctx, d.repository.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return false, err
	}
	versions := make([]int64, 0, len(d.reuse.keys))
	for version := range d.reuse.keys {
		versions = append(versions, int64(version))
	}
	slices.Sort(versions)
	digests := make([][]byte, 0, len(versions))
	for _, version := range versions {
		digest := identifierReuseDigest(d.reuse.keys[uint32(version)], q.TenantID, "username", q.CanonicalValue)
		digests = append(digests, slices.Clone(digest[:]))
	}
	var occupied, missingKey, cooling bool
	err := d.repository.pool.Raw().QueryRow(bounded, `WITH retained(key_version,value_digest) AS (SELECT * FROM unnest($3::bigint[],$4::bytea[]))
SELECT EXISTS(SELECT 1 FROM identity.identifiers WHERE tenant_id=$1 AND kind='username' AND canonical_value=$2),
 EXISTS(SELECT 1 FROM identity.identifier_retirements r WHERE r.tenant_id=$1 AND r.kind='username' AND r.reuse_until>statement_timestamp() AND NOT EXISTS(SELECT 1 FROM retained k WHERE k.key_version=r.key_version)),
 EXISTS(SELECT 1 FROM identity.identifier_retirements r JOIN retained k ON k.key_version=r.key_version AND k.value_digest=r.value_digest WHERE r.tenant_id=$1 AND r.kind='username' AND r.reuse_until>statement_timestamp())`, string(q.TenantID), q.CanonicalValue, versions, digests).Scan(&occupied, &missingKey, &cooling)
	if err != nil {
		return false, readFailure(bounded, err)
	}
	if err := bounded.Err(); err != nil {
		return false, err
	}
	if missingKey {
		return false, readFailure(bounded, invalidUsernameLookup())
	}
	return !occupied && !cooling, nil
}
