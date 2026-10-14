package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MigrationSource owns the forward-only issued-evidence install in a dedicated
// namespace. Version is a permanent 1..MaxInt64 allocation in the composition's
// single migration history; never renumber applied versions. Kernel migrations
// must precede this source. Existing unmanaged objects fail instead of being
// adopted. Zero is invalid; Load is pure and concurrent-safe. This initial
// history does not implement reservations, counters, CAPTCHA or erasure.
type MigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = MigrationSource{}

// Load returns independently owned atomic installation SQL without a destructive
// down migration. Invalid input is redacted; context cancellation is preserved.
func (s MigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(issueSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_issued_evidence", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

func validSchema(s string) bool {
	if len(s) == 0 || len(s) > 63 || s == "public" || s == "identity" || s == "information_schema" || strings.HasPrefix(s, "pg_") {
		return false
	}
	for i := range len(s) {
		if !(s[i] >= 'a' && s[i] <= 'z' || s[i] == '_' || i > 0 && s[i] >= '0' && s[i] <= '9') {
			return false
		}
	}
	return true
}

// Minimal structural identifiers and scoped keyed digests are retained, never
// raw phone/network/attempt/provider facts. The command FK prevents authority
// retirement while this immutable native recovery evidence depends on it.
// No cleanup path deletes these rows; expiry alone is not rollback evidence.
const issueSchemaSQL = `CREATE SCHEMA @schema@;
CREATE TABLE @schema@.issued_evidence(
 tenant_id text COLLATE "C" NOT NULL CHECK(tenant_id ~ '^[!-~]{1,128}$'),
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 command_purpose text COLLATE "C" NOT NULL CHECK(command_purpose='identity.risk.evaluate'),
 record_id text COLLATE "C" NOT NULL CHECK(record_id ~ '^rei1_[1-9][0-9]{0,9}_[A-Za-z0-9_-]{43}$'),
 user_id text COLLATE "C" NOT NULL CHECK(user_id ~ '^[!-~]{1,128}$'),
 purpose text COLLATE "C" NOT NULL CHECK(purpose IN('phone-password-reset-initiate','phone-password-reset-complete')),
 policy_version numeric NOT NULL CHECK(policy_version>=1 AND policy_version<=18446744073709551615 AND scale(policy_version)=0),
 key_version bigint NOT NULL CHECK(key_version BETWEEN 1 AND 4294967295),
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32 AND binding_digest<>decode(repeat('00',32),'hex')),
 intent_digest bytea NOT NULL CHECK(octet_length(intent_digest)=32 AND intent_digest<>decode(repeat('00',32),'hex')),
 proof_digest bytea NOT NULL CHECK(octet_length(proof_digest)=32 AND proof_digest<>decode(repeat('00',32),'hex')),
 evidence_digest bytea NOT NULL CHECK(octet_length(evidence_digest)=32 AND evidence_digest<>decode(repeat('00',32),'hex')),
 issued_at timestamptz NOT NULL CHECK(isfinite(issued_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
 state text COLLATE "C" NOT NULL CHECK(state='issued'),
 response_envelope bytea NOT NULL CHECK(octet_length(response_envelope) BETWEEN 100 AND 1024),
 PRIMARY KEY(tenant_id,record_id),
 UNIQUE(command_id),
 UNIQUE(tenant_id,purpose,key_version,evidence_digest),
 FOREIGN KEY(command_id,tenant_id,command_purpose) REFERENCES identity.commands(command_id,tenant_id,purpose),
 CHECK(expires_at>issued_at AND expires_at-issued_at<=interval '2 minutes')
);
CREATE INDEX risk_issued_expiry_order ON @schema@.issued_evidence(expires_at,tenant_id,record_id);
CREATE INDEX risk_issued_subject_order ON @schema@.issued_evidence(tenant_id,user_id,record_id);
`
