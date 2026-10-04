package postgres

import (
	"context"
	"crypto/hmac"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5/pgxpool"
)

// retainedPolicies is immutable deployment configuration, not a retry engine.
// PostgreSQL owns version identity; constructors atomically register an entire
// bounded snapshot and reject reinterpretation of any previously installed key.
// Keep every referenced profile available across restarts. No fallback is allowed.
type retainedPolicies struct {
	pool       *pgxpool.Pool
	deployment string
	profiles   map[uint64]delivery.Config
	timeout    time.Duration
}

func newRetainedPolicies(ctx context.Context, pool *pgxpool.Pool, deployment string, profiles map[uint64]delivery.Config, timeout time.Duration) (*retainedPolicies, error) {
	if ctx == nil || pool == nil || !safeID(deployment, false) || len(profiles) < 1 || len(profiles) > 32 || timeout < time.Second || timeout > 30*time.Second {
		return nil, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	owned := make(map[uint64]delivery.Config, len(profiles))
	versions := make([]uint64, 0, len(profiles))
	for version, config := range profiles {
		if version == 0 || config.Validate() != nil {
			return nil, delivery.ErrInvalidInput
		}
		config.BackoffCeilings = slices.Clone(config.BackoffCeilings)
		owned[version] = config
		versions = append(versions, version)
	}
	// Consistent insertion order prevents opposite configuration maps taking
	// uniqueness locks in opposite order during concurrent rolling restarts.
	slices.Sort(versions)
	w, stop := context.WithTimeout(ctx, timeout)
	defer stop()
	tx, err := pool.Begin(w)
	if err != nil {
		return nil, attemptFailure(w, err)
	}
	defer rollbackAttempt(tx)
	for _, version := range versions {
		key := strconv.FormatUint(version, 10)
		digest := attemptPolicyDigest(owned[version], timeout)
		if _, err := tx.Exec(w, `INSERT INTO identity.delivery_policy_profiles(deployment,policy_version,config_digest) VALUES($1,$2,$3) ON CONFLICT(deployment,policy_version) DO NOTHING`, deployment, key, digest[:]); err != nil {
			return nil, attemptFailure(w, err)
		}
		var installed []byte
		if err := tx.QueryRow(w, `SELECT config_digest FROM identity.delivery_policy_profiles WHERE deployment=$1 AND policy_version=$2`, deployment, key).Scan(&installed); err != nil {
			return nil, attemptFailure(w, err)
		}
		if !hmac.Equal(installed, digest[:]) {
			return nil, delivery.ErrConflict
		}
	}
	if err := tx.Commit(w); err != nil {
		// Re-registering this exact snapshot is safe, but a lost acknowledgement
		// cannot be reported as successful configuration installation.
		return nil, delivery.ErrOutcomeUnknown
	}
	return &retainedPolicies{pool, deployment, owned, timeout}, nil
}

func (p *retainedPolicies) worker(version uint64, codec *payloadCodec) (*attemptStore, error) {
	if p == nil || version == 0 {
		return nil, delivery.ErrInvalidInput
	}
	config, ok := p.profiles[version]
	if !ok {
		return nil, delivery.ErrUnavailable
	}
	worker, err := newAttemptStore(p.pool, p.deployment, codec, config, p.timeout)
	if err != nil {
		return nil, err
	}
	worker.retainedVersion = version
	return worker, nil
}

// New immutable extension: admission and attempt migrations stay unchanged.
// Profiles contain only a bounded configuration fingerprint, never credentials.
const policySchemaSQL = `
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
CREATE TABLE identity.delivery_policy_profiles (
 deployment identity.directory_id NOT NULL,
 policy_version identity.version NOT NULL,
 config_digest bytea NOT NULL CHECK (octet_length(config_digest)=32),
 PRIMARY KEY(deployment,policy_version)
);
CREATE FUNCTION identity.guard_delivery_policy_profiles() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'immutable delivery policy history' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER identity_delivery_policy_immutable BEFORE UPDATE OR DELETE ON identity.delivery_policy_profiles FOR EACH STATEMENT EXECUTE FUNCTION identity.guard_delivery_policy_profiles();
CREATE TRIGGER identity_delivery_policy_no_truncate BEFORE TRUNCATE ON identity.delivery_policy_profiles FOR EACH STATEMENT EXECUTE FUNCTION identity.guard_delivery_policy_profiles();
`
