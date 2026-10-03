package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// VelocityMigrationSource appends the PostgreSQL recovery journal and boot-epoch
// storage for ephemeral Valkey counters. It does not grant counter mutation,
// replay, pruning, or healthy-publication authority. Allocate Version permanently
// after Base.Version. Load is pure/concurrent-safe and preserves installed SQL.
// No epoch or healthy state is manufactured by installation.
type VelocityMigrationSource struct {
	Base    CounterMigrationSource
	Version migrations.Version
}

var _ migrations.Source = VelocityMigrationSource{}

// Load returns owned forward-only atomic history. Invalid allocations fail
// redacted; base validation preserves nil-context and cancellation semantics.
func (s VelocityMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.Base.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(velocitySchemaSQL, "@schema@", pgx.Identifier{s.Base.Base.Base.Base.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_velocity_recovery", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(history, m), nil
}

// Sequence numbers are scan positions, not commit-order or completeness proofs.
// The native recovery owner must fence writers/replay and validate full target
// cardinality before publication. SQL constrains storage, not runtime authority.
// Attempts are keyed digests, never raw request IDs; ambiguity has no expiry.
const velocitySchemaSQL = `CREATE TABLE @schema@.velocity_attempts(
 sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id text COLLATE "C" NOT NULL CHECK(tenant_id ~ '^[!-~]{1,128}$'),
 namespace_digest bytea NOT NULL CHECK(octet_length(namespace_digest)=32 AND namespace_digest<>decode(repeat('00',32),'hex')),
 operation text COLLATE "C" NOT NULL CHECK(operation ~ '^[a-z][a-z0-9._-]{0,127}$'),
 phase text COLLATE "C" NOT NULL CHECK(phase IN('before_credential_or_provider_work','before_return')),
 policy_version numeric NOT NULL CHECK(policy_version BETWEEN 1 AND 18446744073709551615 AND scale(policy_version)=0),
 attempt_digest bytea NOT NULL CHECK(octet_length(attempt_digest)=32 AND attempt_digest<>decode(repeat('00',32),'hex')),
 counter_fingerprint bytea NOT NULL CHECK(octet_length(counter_fingerprint)=32 AND counter_fingerprint<>decode(repeat('00',32),'hex')),
 prepared_at timestamptz NOT NULL CHECK(isfinite(prepared_at)),
 recorded_at timestamptz NOT NULL CHECK(isfinite(recorded_at) AND recorded_at>=prepared_at),
 window_us bigint NOT NULL CHECK(window_us BETWEEN 1 AND 3600000000),
 attempt_limit bigint NOT NULL CHECK(attempt_limit BETWEEN 1 AND 120),
 outcome text COLLATE "C" NOT NULL CHECK(outcome IN('pending','committed','not_committed','unknown')),
 UNIQUE(tenant_id,namespace_digest,operation,phase,attempt_digest),
 UNIQUE(sequence,phase,window_us)
);
CREATE TABLE @schema@.velocity_snapshots(
 sequence bigint NOT NULL,phase text COLLATE "C" NOT NULL,window_us bigint NOT NULL,
 dimension text COLLATE "C" NOT NULL,
 value numeric NOT NULL CHECK(value BETWEEN 0 AND 18446744073709551615 AND scale(value)=0),
 observed_at timestamptz NOT NULL CHECK(isfinite(observed_at)),
 started_at timestamptz NOT NULL CHECK(isfinite(started_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>started_at),
 PRIMARY KEY(sequence,dimension),
 FOREIGN KEY(sequence,phase,window_us) REFERENCES @schema@.velocity_attempts(sequence,phase,window_us),
 CHECK((phase='before_credential_or_provider_work' AND dimension IN('tenant','canonical_network','device','canonical_identifier_digest')) OR
       (phase='before_return' AND dimension IN('tenant','subject_or_network'))),
 CHECK(expires_at-started_at=window_us*interval '1 microsecond'),
 CHECK(observed_at>=started_at AND observed_at<expires_at)
);
CREATE TABLE @schema@.velocity_aliases(
 sequence bigint NOT NULL,dimension text COLLATE "C" NOT NULL,
 key_rank smallint NOT NULL CHECK(key_rank BETWEEN 1 AND 4),
 key_version bigint NOT NULL CHECK(key_version BETWEEN 1 AND 4294967295),
 key_id text COLLATE "C" NOT NULL CHECK(key_id ~ '^rv1:[1-9][0-9]{0,9}:[A-Za-z0-9_-]{43}$'),
 PRIMARY KEY(sequence,dimension,key_rank),UNIQUE(sequence,dimension,key_version),
 FOREIGN KEY(sequence,dimension) REFERENCES @schema@.velocity_snapshots,
 CHECK(split_part(key_id,':',2)=key_version::text)
);
CREATE TABLE @schema@.velocity_epochs(
 tenant_id text COLLATE "C" NOT NULL CHECK(tenant_id ~ '^[!-~]{1,128}$'),
 namespace_digest bytea NOT NULL CHECK(octet_length(namespace_digest)=32 AND namespace_digest<>decode(repeat('00',32),'hex')),
 epoch bytea NOT NULL CHECK(octet_length(epoch)=16 AND epoch<>decode(repeat('00',16),'hex')),
 generation numeric NOT NULL CHECK(generation BETWEEN 1 AND 18446744073709551615 AND scale(generation)=0),
 maximum_window_us bigint NOT NULL CHECK(maximum_window_us BETWEEN 1 AND 3600000000),
 state text COLLATE "C" NOT NULL DEFAULT 'unavailable' CHECK(state IN('unavailable','replaying','healthy','retired')),
 lease_owner bytea,lease_expires_at timestamptz,
 replay_from timestamptz,replay_through timestamptz,healthy_at timestamptz,
 PRIMARY KEY(tenant_id,namespace_digest,epoch),
 CHECK((lease_owner IS NULL AND lease_expires_at IS NULL) OR
       (lease_owner IS NOT NULL AND octet_length(lease_owner)=16 AND lease_owner<>decode(repeat('00',16),'hex') AND lease_expires_at IS NOT NULL AND isfinite(lease_expires_at))),
 CHECK((replay_from IS NULL AND replay_through IS NULL) OR
       (replay_from IS NOT NULL AND replay_through IS NOT NULL AND isfinite(replay_from) AND isfinite(replay_through) AND replay_from<=replay_through)),
 CHECK(state<>'replaying' OR lease_owner IS NOT NULL),
 CHECK((state='healthy' AND healthy_at IS NOT NULL AND isfinite(healthy_at) AND replay_from IS NOT NULL AND replay_through IS NOT NULL AND replay_from<=healthy_at-maximum_window_us*interval '1 microsecond' AND replay_through>=healthy_at) OR
       (state<>'healthy' AND healthy_at IS NULL))
);
CREATE UNIQUE INDEX risk_velocity_active_epoch ON @schema@.velocity_epochs(tenant_id,namespace_digest) WHERE state<>'retired';
CREATE INDEX risk_velocity_replay ON @schema@.velocity_attempts(tenant_id,namespace_digest,recorded_at,sequence);
`
