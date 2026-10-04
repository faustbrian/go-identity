package postgres

// This forward extension leaves the installed intent migration byte-for-byte
// intact. These are delivery-specific effect fences/outcomes, not a second
// generic workflow or outbox engine. Legacy submitted rows with no processing
// record cannot be reissued by this worker. No provider reference is plaintext.
const attemptSchemaSQL = `
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
CREATE TABLE identity.delivery_processing (
 deployment identity.directory_id NOT NULL,
 tenant_id identity.directory_id NOT NULL,
 effect_id text COLLATE "C" NOT NULL,
 generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 4294967295),
 attempt_number smallint NOT NULL CHECK (attempt_number BETWEEN 1 AND 10),
 policy_digest bytea NOT NULL CHECK (octet_length(policy_digest)=32),
 lease_owner identity.directory_id,
 lease_until timestamptz CHECK (isfinite(lease_until)),
 next_attempt_at timestamptz CHECK (isfinite(next_attempt_at)),
 cancel_requested boolean NOT NULL DEFAULT false,
 PRIMARY KEY(deployment,tenant_id,effect_id),
 FOREIGN KEY(deployment,tenant_id,effect_id) REFERENCES identity.delivery_intents,
 CHECK ((lease_owner IS NULL)=(lease_until IS NULL)),
 CHECK (lease_until IS NULL OR next_attempt_at IS NULL)
);
CREATE INDEX identity_delivery_retry_due ON identity.delivery_processing(deployment,tenant_id,next_attempt_at,effect_id) WHERE next_attempt_at IS NOT NULL;
CREATE INDEX identity_delivery_lease_due ON identity.delivery_processing(deployment,tenant_id,lease_until,effect_id) WHERE lease_until IS NOT NULL;
CREATE INDEX identity_delivery_pending ON identity.delivery_intents(deployment,tenant_id,created_at,effect_id) WHERE state IN ('planned','retry-wait');
CREATE INDEX identity_delivery_custody_expiry ON identity.delivery_intents(deployment,tenant_id,expires_at,effect_id) WHERE ciphertext IS NOT NULL AND state IN ('planned','retry-wait','submitted','outcome-unknown');
CREATE TABLE identity.delivery_attempt_history (
 deployment identity.directory_id NOT NULL,
 tenant_id identity.directory_id NOT NULL,
 effect_id text COLLATE "C" NOT NULL,
 generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 4294967295),
 attempt_number smallint NOT NULL CHECK (attempt_number BETWEEN 1 AND 10),
 worker identity.directory_id NOT NULL,
 started_at timestamptz NOT NULL CHECK (isfinite(started_at)),
 lease_until timestamptz NOT NULL CHECK (isfinite(lease_until) AND lease_until>started_at AND lease_until<=started_at+INTERVAL '60 seconds'),
 outcome smallint CHECK (outcome BETWEEN 1 AND 12 AND outcome<>2),
 completed_at timestamptz CHECK (isfinite(completed_at)),
 completion_digest bytea CHECK (octet_length(completion_digest)=32),
 provider_reference_digest bytea CHECK (octet_length(provider_reference_digest)=32),
 PRIMARY KEY(deployment,tenant_id,effect_id,generation),
 FOREIGN KEY(deployment,tenant_id,effect_id) REFERENCES identity.delivery_processing,
 CHECK ((outcome IS NULL)=(completed_at IS NULL)),
 CHECK (completion_digest IS NULL OR outcome IS NOT NULL)
);
`
