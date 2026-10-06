// Package postgres owns durable OTP storage in the identity coordinator's
// transaction domain. Native admission and workflow execution are in development;
// installing storage alone does not verify a code or confer OTP authority.
package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MigrationSource installs forward-only OTP challenge custody in a dedicated
// namespace after the identity kernel. Version is a permanent allocation in
// the composition's single migration history, in 1..MaxInt64; never renumber an
// applied migration. Existing namespaces fail instead of being adopted. Zero
// is invalid. Load is pure and concurrent-safe and creates no migration runner.
// This install does not yet provide issuance, send limits or participant APIs.
type MigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = MigrationSource{}

// Load returns independently owned atomic installation SQL without destructive
// down SQL. Invalid configuration is redacted; context cancellation is retained.
func (s MigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "otp_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(challengeSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_otp_challenge_custody", migrations.TransactionModeDefault, sql, "")
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

// Scope and code digests use the same explicitly retained core HMAC version.
// No destination, submitted code, bearer, key material or recoverable code is
// stored here. Original policy and timing are immutable; numeric columns keep
// full uint64 width without fractional rounding. Issuance and consumer FKs keep
// the sole coordinator journal alive while unresolved or terminal custody needs
// it. No cleanup API exists in this initial install: tombstones cannot be deleted
// until a later reviewed key-retirement/retention protocol is implemented.
// The guard rejects impossible state/counter changes but does not establish
// current authorization, count idempotency, or authoritative rollback proof.
const challengeSchemaSQL = `CREATE SCHEMA @schema@;
CREATE TABLE @schema@.digest_keys(
 key_version bigint PRIMARY KEY CHECK(key_version BETWEEN 1 AND 4294967295),
 algorithm text COLLATE "C" NOT NULL CHECK(algorithm='hmac-sha256-v1')
);
CREATE TABLE @schema@.challenges(
 tenant_id identity.directory_id NOT NULL,
 challenge_id text COLLATE "C" NOT NULL CHECK(octet_length(challenge_id) BETWEEN 1 AND 256 AND challenge_id !~ '[[:cntrl:]]'),
 subject_id text COLLATE "C" NOT NULL CHECK(octet_length(subject_id)<=256 AND subject_id !~ '[[:cntrl:]]'),
 purpose text COLLATE "C" NOT NULL CHECK(purpose IN('signin','email-verification','password-reset','email-change','mfa','step-up')),
 issue_command_id bytea NOT NULL CHECK(octet_length(issue_command_id)=16),
 issue_command_purpose text COLLATE "C" NOT NULL,
 issue_fingerprint bytea NOT NULL CHECK(octet_length(issue_fingerprint)=32 AND issue_fingerprint<>decode(repeat('00',32),'hex')),
 digest_key_version bigint NOT NULL REFERENCES @schema@.digest_keys(key_version),
 code_digest bytea NOT NULL CHECK(octet_length(code_digest)=32 AND code_digest<>decode(repeat('00',32),'hex')),
 scope_digest bytea NOT NULL CHECK(octet_length(scope_digest)=32 AND scope_digest<>decode(repeat('00',32),'hex')),
 policy_version identity.version NOT NULL,
 scope_generation identity.version NOT NULL,
 alphabet text COLLATE "C" NOT NULL CHECK(octet_length(alphabet) BETWEEN 2 AND 94 AND alphabet ~ '^[!-~]+$'),
 code_length integer NOT NULL CHECK(code_length BETWEEN 4 AND 128),
 ttl_us bigint NOT NULL CHECK(ttl_us BETWEEN 30000000 AND 600000000),
 resend_interval_us bigint NOT NULL CHECK(resend_interval_us BETWEEN 30000000 AND 600000000),
 maximum_sends integer NOT NULL CHECK(maximum_sends BETWEEN 1 AND 10),
 attempt_limit integer NOT NULL CHECK(attempt_limit BETWEEN 1 AND 10),
 replacement text COLLATE "C" NOT NULL CHECK(replacement IN('replace','retain')),
 checks_enabled boolean NOT NULL,
 check_limit integer NOT NULL CHECK(check_limit BETWEEN 0 AND 10),
 lockout_us bigint NOT NULL CHECK(lockout_us BETWEEN 1 AND 86400000000),
 issued_at timestamptz NOT NULL CHECK(issued_at>=timestamptz '0001-01-01 AD' AND issued_at<timestamptz '10000-01-01 AD'),
 expires_at timestamptz NOT NULL CHECK(expires_at>=timestamptz '0001-01-01 AD' AND expires_at<timestamptz '10000-01-01 AD'),
 state text COLLATE "C" NOT NULL CHECK(state IN('issued','reserved','finalized','released','expired','revoked','exhausted')),
 version identity.version NOT NULL,
 used_attempts integer NOT NULL DEFAULT 0,
 failed_attempts integer NOT NULL DEFAULT 0,
 checks integer NOT NULL DEFAULT 0,
 consumer_command_id bytea,
 consumer_purpose text COLLATE "C",
 consumer_fingerprint bytea,
 consumer_generation identity.version,
 consumer_attempt_id text COLLATE "C",
 consumer_attempt_fingerprint bytea,
 consumer_issuer_version bigint,
 reserved_at timestamptz,
 terminal_at timestamptz,
 PRIMARY KEY(tenant_id,challenge_id),
 UNIQUE(issue_command_id),
 UNIQUE(tenant_id,digest_key_version,scope_digest),
 FOREIGN KEY(issue_command_id,tenant_id,issue_command_purpose) REFERENCES identity.commands(command_id,tenant_id,purpose),
 FOREIGN KEY(consumer_command_id,tenant_id,consumer_purpose) REFERENCES identity.commands(command_id,tenant_id,purpose),
 CHECK(expires_at>issued_at AND expires_at-issued_at<=ttl_us*interval '1 microsecond'),
 CHECK((checks_enabled AND check_limit BETWEEN 1 AND 10) OR (NOT checks_enabled AND check_limit=0)),
 CHECK(used_attempts BETWEEN 0 AND attempt_limit AND failed_attempts BETWEEN 0 AND used_attempts AND checks BETWEEN 0 AND used_attempts AND checks<=check_limit),
 CHECK(state<>'issued' OR used_attempts<attempt_limit),
 CHECK(state<>'exhausted' OR used_attempts=attempt_limit),
 CHECK(state NOT IN('reserved','finalized','released') OR (used_attempts>failed_attempts AND used_attempts>checks)),
 CHECK(
  (consumer_command_id IS NULL AND consumer_purpose IS NULL AND consumer_fingerprint IS NULL
   AND consumer_generation IS NULL AND consumer_attempt_id IS NULL AND consumer_attempt_fingerprint IS NULL
   AND consumer_issuer_version IS NULL AND reserved_at IS NULL
   AND state IN('issued','expired','revoked','exhausted')
   AND ((state='issued' AND terminal_at IS NULL)
    OR (state<>'issued' AND terminal_at IS NOT NULL AND terminal_at>=issued_at AND terminal_at<timestamptz '10000-01-01 AD')))
  OR
  (consumer_command_id IS NOT NULL AND consumer_purpose IS NOT NULL AND consumer_fingerprint IS NOT NULL
   AND consumer_generation IS NOT NULL AND consumer_attempt_id IS NOT NULL AND consumer_attempt_fingerprint IS NOT NULL
   AND consumer_issuer_version IS NOT NULL AND reserved_at IS NOT NULL
   AND octet_length(consumer_command_id)=16 AND consumer_command_id<>issue_command_id
   AND octet_length(consumer_fingerprint)=32 AND consumer_fingerprint<>decode(repeat('00',32),'hex')
   AND consumer_attempt_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND consumer_attempt_id<>'AAAAAAAAAAAAAAAAAAAAAA'
   AND octet_length(consumer_attempt_fingerprint)=32 AND consumer_attempt_fingerprint<>decode(repeat('00',32),'hex')
   AND consumer_issuer_version BETWEEN 1 AND 4294967295
   AND reserved_at>=issued_at AND reserved_at<expires_at
   AND ((state='reserved' AND terminal_at IS NULL)
    OR (state IN('finalized','released','revoked') AND terminal_at IS NOT NULL
     AND terminal_at>=reserved_at AND terminal_at<timestamptz '10000-01-01 AD'
     AND (state<>'finalized' OR terminal_at<expires_at))))
 )
);
CREATE INDEX otp_issued_expiry ON @schema@.challenges(expires_at,tenant_id,challenge_id) WHERE state='issued';
CREATE INDEX otp_terminal_retention ON @schema@.challenges(terminal_at,tenant_id,challenge_id) WHERE state IN('finalized','released','expired','revoked','exhausted');
CREATE INDEX otp_consuming_owner ON @schema@.challenges(tenant_id,consumer_command_id) WHERE consumer_command_id IS NOT NULL;

CREATE FUNCTION @schema@.guard_challenge() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $guard$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP custody retention required'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'issued' OR NEW.version<>1 OR NEW.used_attempts<>0 OR NEW.failed_attempts<>0 OR NEW.checks<>0 THEN
   RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP initial custody conflict';
  END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.tenant_id,NEW.challenge_id,NEW.subject_id,NEW.purpose,NEW.issue_command_id,NEW.issue_command_purpose,NEW.issue_fingerprint,
        NEW.digest_key_version,NEW.code_digest,NEW.scope_digest,NEW.policy_version,NEW.scope_generation,
        NEW.alphabet,NEW.code_length,NEW.ttl_us,NEW.resend_interval_us,NEW.maximum_sends,NEW.attempt_limit,NEW.replacement,
        NEW.checks_enabled,NEW.check_limit,NEW.lockout_us,NEW.issued_at,NEW.expires_at)
 IS DISTINCT FROM
    ROW(OLD.tenant_id,OLD.challenge_id,OLD.subject_id,OLD.purpose,OLD.issue_command_id,OLD.issue_command_purpose,OLD.issue_fingerprint,
        OLD.digest_key_version,OLD.code_digest,OLD.scope_digest,OLD.policy_version,OLD.scope_generation,
        OLD.alphabet,OLD.code_length,OLD.ttl_us,OLD.resend_interval_us,OLD.maximum_sends,OLD.attempt_limit,OLD.replacement,
        OLD.checks_enabled,OLD.check_limit,OLD.lockout_us,OLD.issued_at,OLD.expires_at)
 OR NEW.version<>OLD.version+1 THEN
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP immutable custody or version conflict';
 END IF;
 IF OLD.state='issued' THEN
  IF NEW.state IN('issued','reserved','exhausted') THEN
   IF NEW.used_attempts<>OLD.used_attempts+1 OR NEW.failed_attempts NOT BETWEEN OLD.failed_attempts AND OLD.failed_attempts+1
    OR NEW.checks NOT BETWEEN OLD.checks AND OLD.checks+1
    OR (NEW.state='reserved' AND (NEW.failed_attempts<>OLD.failed_attempts OR NEW.checks<>OLD.checks))
    OR (NEW.state IN('issued','exhausted') AND NEW.failed_attempts=OLD.failed_attempts AND NEW.checks=OLD.checks) THEN
     RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP counted transition conflict';
   END IF;
  ELSIF NEW.state IN('expired','revoked') THEN
   IF ROW(NEW.used_attempts,NEW.failed_attempts,NEW.checks) IS DISTINCT FROM ROW(OLD.used_attempts,OLD.failed_attempts,OLD.checks)
    OR (NEW.state='expired' AND NEW.terminal_at<OLD.expires_at) THEN
     RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP terminal transition conflict';
   END IF;
  ELSE RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP lifecycle conflict';
  END IF;
 ELSIF OLD.state='reserved' THEN
  IF NEW.state NOT IN('reserved','finalized','released','revoked')
   OR ROW(NEW.used_attempts,NEW.failed_attempts,NEW.checks,NEW.consumer_command_id,NEW.consumer_purpose,
          NEW.consumer_fingerprint,NEW.consumer_attempt_id,NEW.consumer_attempt_fingerprint,NEW.consumer_issuer_version,NEW.reserved_at)
    IS DISTINCT FROM ROW(OLD.used_attempts,OLD.failed_attempts,OLD.checks,OLD.consumer_command_id,OLD.consumer_purpose,
          OLD.consumer_fingerprint,OLD.consumer_attempt_id,OLD.consumer_attempt_fingerprint,OLD.consumer_issuer_version,OLD.reserved_at)
   OR (NEW.state='reserved' AND NEW.consumer_generation<=OLD.consumer_generation)
   OR (NEW.state='released' AND NEW.consumer_generation NOT IN(OLD.consumer_generation,OLD.consumer_generation+1))
   OR (NEW.state IN('finalized','revoked') AND NEW.consumer_generation<>OLD.consumer_generation) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP reservation custody conflict';
  END IF;
 ELSE RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP terminal custody is immutable';
 END IF;
 RETURN NEW;
END
$guard$;
CREATE TRIGGER otp_challenge_guard BEFORE INSERT OR UPDATE OR DELETE ON @schema@.challenges FOR EACH ROW EXECUTE FUNCTION @schema@.guard_challenge();
`
