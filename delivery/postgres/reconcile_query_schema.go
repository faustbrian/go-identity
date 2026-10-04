package postgres

// Query metadata projects the original protected command, not another command
// journal. Sensitive cursor custody is separately erasable; immutable results
// retain only scoped commitments so historical replay survives terminal erasure.
const reconciliationQuerySchemaSQL = `
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
CREATE TABLE identity.delivery_reconciliation_queries (
 deployment identity.directory_id NOT NULL,
 tenant_id identity.directory_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 query_digest bytea NOT NULL CHECK(octet_length(query_digest)=32),
 provider_version identity.version NOT NULL,
 query_state smallint NOT NULL CHECK(query_state IN(3,4,5,6,7,8,13)),
 observed_at timestamptz NOT NULL CHECK(isfinite(observed_at)),
 retry_after_ns bigint NOT NULL CHECK(retry_after_ns BETWEEN 0 AND 120000000000),
 CHECK(query_state=13 OR retry_after_ns=0),
 PRIMARY KEY(deployment,tenant_id,command_id),
 FOREIGN KEY(deployment,tenant_id,command_id) REFERENCES identity.delivery_reconciliation_commands(deployment,tenant_id,command_id)
);
CREATE TRIGGER identity_delivery_reconciliation_query_immutable BEFORE UPDATE OR DELETE ON identity.delivery_reconciliation_queries
 FOR EACH ROW EXECUTE FUNCTION identity.delivery_receipt_immutable();
CREATE TRIGGER identity_delivery_reconciliation_query_no_truncate BEFORE TRUNCATE ON identity.delivery_reconciliation_queries
 FOR EACH STATEMENT EXECUTE FUNCTION identity.delivery_receipt_immutable();
CREATE TABLE identity.delivery_reconciliation_cursors (
 deployment identity.directory_id NOT NULL,
 tenant_id identity.directory_id NOT NULL,
 effect_id text COLLATE "C" NOT NULL,
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 4294967295),
 step bigint NOT NULL CHECK(step>0),
 provider identity.directory_id NOT NULL,
 provider_version identity.version NOT NULL,
 cursor_digest bytea NOT NULL CHECK(octet_length(cursor_digest)=32),
 key_id identity.directory_id NOT NULL,
 digest_key_version bigint NOT NULL CHECK(digest_key_version BETWEEN 1 AND 4294967295),
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) BETWEEN 33 AND 8192),
 PRIMARY KEY(deployment,tenant_id,effect_id,generation),
 FOREIGN KEY(deployment,tenant_id,effect_id,provider) REFERENCES identity.delivery_intents(deployment,tenant_id,effect_id,provider),
 FOREIGN KEY(deployment,tenant_id,effect_id,generation,step) REFERENCES identity.delivery_reconciliation_checkpoints(deployment,tenant_id,effect_id,generation,step)
);
CREATE FUNCTION identity.delivery_reconciliation_cursor_cleanup() RETURNS trigger
 LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state NOT IN('outcome-unknown','submitted') THEN
  DELETE FROM identity.delivery_reconciliation_cursors
   WHERE deployment=NEW.deployment AND tenant_id=NEW.tenant_id AND effect_id=NEW.effect_id;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER identity_delivery_reconciliation_cursor_cleanup AFTER UPDATE OF state ON identity.delivery_intents
 FOR EACH ROW EXECUTE FUNCTION identity.delivery_reconciliation_cursor_cleanup();
`
