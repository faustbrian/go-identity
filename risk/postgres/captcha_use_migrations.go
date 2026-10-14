package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// CaptchaUseMigrationSource adds consuming-command custody to the existing
// CAPTCHA evidence journal without changing issuance, aliases or envelopes.
// Install CaptchaMigrationSource first and permanently allocate Version after
// installed history. Previously reserved/finalized/released rows without owned
// linkage fail the atomic upgrade: their authority cannot be guessed or reset.
// This schema grants no reservation, release or protected execution authority;
// those operations must use the sole coordinator and native participant CAS.
// Load is pure, cancellation-aware and concurrent-safe; zero is invalid.
type CaptchaUseMigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = CaptchaUseMigrationSource{}

// Load returns an independently owned forward-only atomic migration. Existing
// unmanaged objects and unsupported history fail execution rather than being
// silently adopted. Invalid configuration is redacted; cancellation is retained.
func (s CaptchaUseMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(captchaUseSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_captcha_consuming_custody", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

// Nullable linkage preserves untouched historical evidence. Once a consuming
// state is represented, every ownership scalar must exist; SQL CHECK's NULL
// semantics must not admit partial linkage. Terminal payload erasure leaves the
// command/fingerprint/generation/signature tombstone and both journal references.
// Temporal constraints conserve the original exclusive expiry; release/revoke
// may occur later, but they cannot be interpreted as successful consumption.
// Legal transitions and authoritative noncommit proof remain native CAS duties.
const captchaUseSchemaSQL = `ALTER TABLE @schema@.captcha_issued_evidence
 ADD COLUMN consumer_command_id bytea,
 ADD COLUMN consumer_purpose text COLLATE "C",
 ADD COLUMN consumer_fingerprint bytea,
 ADD COLUMN consumer_generation numeric,
 ADD COLUMN consumer_binding_digest bytea,
 ADD COLUMN consumer_signature bytea,
 ADD COLUMN reserved_at timestamptz,
 ADD COLUMN terminal_at timestamptz,
 ADD CONSTRAINT risk_captcha_consumer_command
 FOREIGN KEY(consumer_command_id,tenant_id,consumer_purpose)
 REFERENCES identity.commands(command_id,tenant_id,purpose),
 ADD CONSTRAINT risk_captcha_consumer_custody CHECK(
  (consumer_command_id IS NULL AND consumer_purpose IS NULL
   AND consumer_fingerprint IS NULL AND consumer_generation IS NULL
   AND consumer_binding_digest IS NULL AND consumer_signature IS NULL
   AND reserved_at IS NULL AND terminal_at IS NULL
   AND state IN('issued','expired','revoked'))
  OR
  (consumer_command_id IS NOT NULL AND consumer_purpose IS NOT NULL
   AND consumer_fingerprint IS NOT NULL AND consumer_generation IS NOT NULL
   AND consumer_binding_digest IS NOT NULL AND consumer_signature IS NOT NULL
   AND reserved_at IS NOT NULL
   AND octet_length(consumer_command_id)=16 AND consumer_command_id<>command_id
   AND consumer_purpose ~ '^[a-z][a-z0-9_.-]{0,127}$'
   AND consumer_purpose<>'identity.risk.captcha-issue'
   AND octet_length(consumer_fingerprint)=32 AND consumer_fingerprint<>decode(repeat('00',32),'hex')
   AND consumer_generation BETWEEN 1 AND 18446744073709551615 AND scale(consumer_generation)=0
   AND octet_length(consumer_binding_digest)=32 AND consumer_binding_digest<>decode(repeat('00',32),'hex')
   AND octet_length(consumer_signature)=32 AND consumer_signature<>decode(repeat('00',32),'hex')
   AND isfinite(reserved_at) AND reserved_at>=issued_at AND reserved_at<expires_at
   AND ((state='reserved' AND terminal_at IS NULL)
    OR (state IN('finalized','released','revoked') AND terminal_at IS NOT NULL
     AND isfinite(terminal_at) AND terminal_at>=reserved_at
     AND (state<>'finalized' OR terminal_at<expires_at))))
 );
CREATE INDEX risk_captcha_consuming_owner
 ON @schema@.captcha_issued_evidence(tenant_id,consumer_command_id)
 WHERE consumer_command_id IS NOT NULL;
`
