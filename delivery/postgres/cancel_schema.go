package postgres

// A domain result under the original command FK, not another command journal.
// It remains after current delivery status moves on. No operator text, provider
// references, recipient, ciphertext or rendered content belongs here.
const cancellationSchemaSQL = `
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
CREATE TABLE identity.delivery_cancellations (
 deployment identity.directory_id NOT NULL,
 tenant_id identity.directory_id NOT NULL,
 command_id bytea NOT NULL CHECK (octet_length(command_id)=16),
 command_purpose text COLLATE "C" NOT NULL CHECK (command_purpose='identity.delivery.cancel'),
 effect_id text COLLATE "C" NOT NULL,
 subject_id identity.directory_id NOT NULL,
 binding_digest bytea NOT NULL CHECK (octet_length(binding_digest)=32),
 generation bigint NOT NULL CHECK (generation BETWEEN 0 AND 4294967295),
 before_version identity.version NOT NULL,
 after_version identity.version NOT NULL CHECK (after_version=before_version+1),
 result_state smallint NOT NULL CHECK (result_state IN (4,5,6,7,8,10,11,12)),
 local_cancelled boolean NOT NULL CHECK (NOT local_cancelled OR result_state IN (7,8)),
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK (isfinite(occurred_at)),
 PRIMARY KEY(deployment,tenant_id,command_id),
 FOREIGN KEY(tenant_id,command_purpose,command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 FOREIGN KEY(deployment,tenant_id,effect_id) REFERENCES identity.delivery_intents(deployment,tenant_id,effect_id)
);
CREATE FUNCTION identity.delivery_cancellation_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION USING MESSAGE='delivery cancellation result is immutable',ERRCODE='23514';
END $$;
CREATE TRIGGER identity_delivery_cancellation_immutable BEFORE UPDATE OR DELETE ON identity.delivery_cancellations
 FOR EACH ROW EXECUTE FUNCTION identity.delivery_cancellation_immutable();
CREATE TRIGGER identity_delivery_cancellation_no_truncate BEFORE TRUNCATE ON identity.delivery_cancellations
 FOR EACH STATEMENT EXECUTE FUNCTION identity.delivery_cancellation_immutable();
`
