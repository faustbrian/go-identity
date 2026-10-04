package postgres

// Immutable keyed query progress, not a reservation/command journal. Each row
// shares the receipt's atomic effect boundary. Raw provider cursors never enter
// this projection; a public composition must separately own recoverable custody.
const reconciliationSchemaSQL = `
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
CREATE TABLE identity.delivery_reconciliation_checkpoints (
 deployment identity.directory_id NOT NULL,
 tenant_id identity.directory_id NOT NULL,
 effect_id text COLLATE "C" NOT NULL,
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 4294967295),
 step bigint NOT NULL CHECK(step>0),
 provider identity.directory_id NOT NULL,
 event_digest bytea NOT NULL CHECK(octet_length(event_digest)=32),
 before_digest bytea NOT NULL CHECK(octet_length(before_digest)=32),
 after_digest bytea NOT NULL CHECK(octet_length(after_digest)=32),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(recorded_at)),
 PRIMARY KEY(deployment,tenant_id,provider,event_digest),
 UNIQUE(deployment,tenant_id,effect_id,generation,step),
 FOREIGN KEY(deployment,tenant_id,effect_id,generation) REFERENCES identity.delivery_attempt_history(deployment,tenant_id,effect_id,generation),
 FOREIGN KEY(deployment,tenant_id,provider,event_digest) REFERENCES identity.delivery_receipts(deployment,tenant_id,provider,event_digest)
);
CREATE TRIGGER identity_delivery_reconciliation_immutable BEFORE UPDATE OR DELETE ON identity.delivery_reconciliation_checkpoints
 FOR EACH ROW EXECUTE FUNCTION identity.delivery_receipt_immutable();
CREATE TRIGGER identity_delivery_reconciliation_no_truncate BEFORE TRUNCATE ON identity.delivery_reconciliation_checkpoints
 FOR EACH STATEMENT EXECUTE FUNCTION identity.delivery_receipt_immutable();
`
