package postgres

// Immutable redacted provider evidence, not another command journal. The
// namespace key is the existing immutable deployment registration; event and
// evidence digests contain no raw provider ID, callback body or recipient.
const receiptSchemaSQL = `
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
ALTER TABLE identity.delivery_intents
 ADD CONSTRAINT identity_delivery_provider_binding UNIQUE(deployment,tenant_id,effect_id,provider);
CREATE TABLE identity.delivery_receipts (
 deployment identity.directory_id NOT NULL,
 tenant_id identity.directory_id NOT NULL,
 provider identity.directory_id NOT NULL,
 event_digest bytea NOT NULL CHECK (octet_length(event_digest)=32),
 evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest)=32),
 effect_id text COLLATE "C" NOT NULL,
 generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 4294967295),
 result_state smallint NOT NULL CHECK (result_state BETWEEN 2 AND 12),
 advanced boolean NOT NULL,
 observed_at timestamptz CHECK (isfinite(observed_at)),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK (isfinite(recorded_at)),
 PRIMARY KEY(deployment,tenant_id,provider,event_digest),
 FOREIGN KEY(deployment,tenant_id,effect_id,provider) REFERENCES identity.delivery_intents(deployment,tenant_id,effect_id,provider),
 FOREIGN KEY(deployment,tenant_id,effect_id,generation) REFERENCES identity.delivery_attempt_history(deployment,tenant_id,effect_id,generation)
);
CREATE INDEX identity_delivery_receipt_observation ON identity.delivery_receipts(deployment,tenant_id,effect_id,generation,observed_at DESC NULLS LAST,event_digest);
CREATE FUNCTION identity.delivery_receipt_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION USING MESSAGE='delivery receipt is immutable',ERRCODE='23514';
END $$;
CREATE TRIGGER identity_delivery_receipt_immutable BEFORE UPDATE OR DELETE ON identity.delivery_receipts
 FOR EACH ROW EXECUTE FUNCTION identity.delivery_receipt_immutable();
CREATE TRIGGER identity_delivery_receipt_no_truncate BEFORE TRUNCATE ON identity.delivery_receipts
 FOR EACH STATEMENT EXECUTE FUNCTION identity.delivery_receipt_immutable();
`
