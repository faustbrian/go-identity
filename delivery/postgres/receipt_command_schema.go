package postgres

// Redacted immutable result of the original kernel command. There is no
// reservation, lease, authority or competing journal/replay state machine.
const receiptCommandSchemaSQL = `
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
CREATE TABLE identity.delivery_receipt_commands (
 deployment identity.directory_id NOT NULL,
 tenant_id identity.directory_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 command_purpose text COLLATE "C" NOT NULL CHECK(command_purpose='identity.delivery.receipt-record'),
 effect_id text COLLATE "C" NOT NULL,
 subject_id identity.directory_id NOT NULL,
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 provider identity.directory_id NOT NULL,
 event_digest bytea NOT NULL CHECK(octet_length(event_digest)=32),
 evidence_digest bytea NOT NULL CHECK(octet_length(evidence_digest)=32),
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 4294967295),
 before_version identity.version NOT NULL,
 after_version identity.version NOT NULL CHECK(after_version=before_version+1),
 result_state smallint NOT NULL CHECK(result_state BETWEEN 2 AND 12),
 advanced boolean NOT NULL,
 deduplicated boolean NOT NULL CHECK(NOT deduplicated OR NOT advanced),
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(occurred_at)),
 PRIMARY KEY(deployment,tenant_id,command_id),
 FOREIGN KEY(tenant_id,command_purpose,command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 FOREIGN KEY(deployment,tenant_id,effect_id,provider) REFERENCES identity.delivery_intents(deployment,tenant_id,effect_id,provider),
 FOREIGN KEY(deployment,tenant_id,provider,event_digest) REFERENCES identity.delivery_receipts(deployment,tenant_id,provider,event_digest)
);
CREATE TRIGGER identity_delivery_receipt_command_immutable BEFORE UPDATE OR DELETE ON identity.delivery_receipt_commands
 FOR EACH ROW EXECUTE FUNCTION identity.delivery_receipt_immutable();
CREATE TRIGGER identity_delivery_receipt_command_no_truncate BEFORE TRUNCATE ON identity.delivery_receipt_commands
 FOR EACH STATEMENT EXECUTE FUNCTION identity.delivery_receipt_immutable();
`
