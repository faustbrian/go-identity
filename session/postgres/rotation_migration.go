package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// RotationMigrationSource adds digest retirement and immutable terminal rotation
// evidence. Schema must match the installed base, and Version is a permanent
// 1..MaxInt64 slot after that base. It rewrites no existing payload or checksum.
// Install with the sole migration runner; no destructive rollback or evidence
// cleanup is supplied. Terminal evidence must outlive prunable session payloads.
type RotationMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns owned forward-only history without IO. Invalid or cancelled
// input fails before composition; duplicate/unmanaged tables are not adopted.
func (s RotationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_rotation_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(rotationSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_session_rotations", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

// The shared command FK retains sole-journal authority; no session payload FK
// can cascade away retirement or participant evidence during privacy cleanup.
const rotationSchemaSQL = `CREATE TABLE @schema@.session_rotations(
 tenant_id @schema@.scope_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.session.refresh'),
 user_id @schema@.scope_id NOT NULL,
 session_id @schema@.scope_id NOT NULL,
 family_id @schema@.scope_id NOT NULL,
 before_version @schema@.version NOT NULL,
 after_version @schema@.version NOT NULL,
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
 successor_digest bytea NOT NULL CHECK(octet_length(successor_digest)=32),
 intent_digest bytea NOT NULL CHECK(octet_length(intent_digest)=32),
 source_record jsonb NOT NULL CHECK(jsonb_typeof(source_record)='object' AND octet_length(source_record::text)<=32768),
 successor_record jsonb NOT NULL CHECK(jsonb_typeof(successor_record)='object' AND octet_length(successor_record::text)<=32768),
 PRIMARY KEY(tenant_id,command_id),
 UNIQUE(tenant_id,session_id,before_version),
 FOREIGN KEY(command_id,tenant_id,purpose) REFERENCES identity.commands(command_id,tenant_id,purpose),
 CHECK(after_version=before_version+1)
);
LOCK TABLE @schema@.sessions IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE @schema@.token_claims(
 tenant_id @schema@.scope_id NOT NULL,
 digest_version bigint NOT NULL CHECK(digest_version BETWEEN 1 AND 4294967295),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 session_id @schema@.scope_id NOT NULL,
 retired boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,digest_version,digest)
);
INSERT INTO @schema@.token_claims(tenant_id,digest_version,digest,session_id)
 SELECT tenant_id,digest_version,digest,session_id FROM @schema@.sessions;
CREATE TABLE @schema@.retired_tokens(
 tenant_id @schema@.scope_id NOT NULL,
 digest_version bigint NOT NULL CHECK(digest_version BETWEEN 1 AND 4294967295),
 digest bytea NOT NULL CHECK(octet_length(digest)=32 AND digest<>decode(repeat('00',32),'hex')),
 user_id @schema@.scope_id NOT NULL,
 session_id @schema@.scope_id NOT NULL,
 family_id @schema@.scope_id NOT NULL,
 before_version @schema@.version NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 expires_at @schema@.instant NOT NULL,
 PRIMARY KEY(tenant_id,digest_version,digest),
 FOREIGN KEY(tenant_id,command_id) REFERENCES @schema@.session_rotations(tenant_id,command_id),
 FOREIGN KEY(tenant_id,digest_version,digest) REFERENCES @schema@.token_claims(tenant_id,digest_version,digest)
);
CREATE INDEX retired_token_family ON @schema@.retired_tokens(tenant_id,family_id);
CREATE FUNCTION @schema@.guard_token_claim() RETURNS trigger
 LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $guard$
BEGIN
 IF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'session token claim is terminal' USING ERRCODE='23514';
 END IF;
 IF ROW(NEW.tenant_id,NEW.digest_version,NEW.digest,NEW.session_id) IS DISTINCT FROM
    ROW(OLD.tenant_id,OLD.digest_version,OLD.digest,OLD.session_id)
    OR (OLD.retired AND NOT NEW.retired) THEN
  RAISE EXCEPTION 'session token claim is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $guard$;
CREATE TRIGGER immutable_token_claim BEFORE UPDATE OR DELETE ON @schema@.token_claims
 FOR EACH ROW EXECUTE FUNCTION @schema@.guard_token_claim();
CREATE FUNCTION @schema@.claim_session_digest() RETURNS trigger
 LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $claim$
DECLARE owner_id text; terminal boolean;
BEGIN
 IF TG_OP='DELETE' THEN
  UPDATE @schema@.token_claims SET retired=true
  WHERE tenant_id=OLD.tenant_id AND digest_version=OLD.digest_version AND digest=OLD.digest;
  RETURN OLD;
 END IF;
 INSERT INTO @schema@.token_claims(tenant_id,digest_version,digest,session_id)
 VALUES(NEW.tenant_id,NEW.digest_version,NEW.digest,NEW.session_id) ON CONFLICT DO NOTHING;
 SELECT session_id,retired INTO STRICT owner_id,terminal FROM @schema@.token_claims
 WHERE tenant_id=NEW.tenant_id AND digest_version=NEW.digest_version AND digest=NEW.digest FOR UPDATE;
 IF owner_id<>NEW.session_id OR terminal THEN
  RAISE EXCEPTION 'session digest unavailable' USING ERRCODE='23505';
 END IF;
 IF TG_OP='UPDATE' AND ROW(OLD.tenant_id,OLD.digest_version,OLD.digest) IS DISTINCT FROM
    ROW(NEW.tenant_id,NEW.digest_version,NEW.digest) THEN
  UPDATE @schema@.token_claims SET retired=true
  WHERE tenant_id=OLD.tenant_id AND digest_version=OLD.digest_version AND digest=OLD.digest;
 END IF;
 RETURN NEW;
END $claim$;
CREATE TRIGGER claim_session_digest BEFORE INSERT OR UPDATE OF tenant_id,session_id,digest_version,digest ON @schema@.sessions
 FOR EACH ROW EXECUTE FUNCTION @schema@.claim_session_digest();
CREATE TRIGGER retire_deleted_session_digest BEFORE DELETE ON @schema@.sessions
 FOR EACH ROW EXECUTE FUNCTION @schema@.claim_session_digest();
CREATE FUNCTION @schema@.require_retired_digest() RETURNS trigger
 LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $retire$
DECLARE owner_id text; terminal boolean;
BEGIN
 SELECT session_id,retired INTO STRICT owner_id,terminal FROM @schema@.token_claims
 WHERE tenant_id=NEW.tenant_id AND digest_version=NEW.digest_version AND digest=NEW.digest FOR UPDATE;
 IF owner_id<>NEW.session_id OR NOT terminal THEN
  RAISE EXCEPTION 'session digest not retired' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $retire$;
CREATE TRIGGER require_retired_digest BEFORE INSERT ON @schema@.retired_tokens
 FOR EACH ROW EXECUTE FUNCTION @schema@.require_retired_digest();
`
