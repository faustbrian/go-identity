package postgres

// Only the coordinator may write these tables. This foundation does not yet
// expose admission or a complete journal/participant/retention implementation.
// The global PK has no cascading-delete path. Retirement must first remove its
// terminal scoped payload, then clear live bindings in that same transaction.
const commandClaimSchemaSQL = `CREATE TABLE identity.identity_command_id_claims (
 command_id bytea PRIMARY KEY CHECK (octet_length(command_id)=16 AND command_id<>decode('00000000000000000000000000000000','hex')),
 tenant_id identity.directory_id,
 purpose text COLLATE "C" CHECK (octet_length(purpose) BETWEEN 1 AND 128 AND purpose ~ '^[a-z][a-z0-9._:/-]*$'),
 fingerprint bytea CHECK (octet_length(fingerprint)=32),
 fingerprint_key_version bigint CHECK (fingerprint_key_version BETWEEN 1 AND 4294967295),
 safe_fields bytea CHECK (octet_length(safe_fields) BETWEEN 1 AND 65536),
 retired boolean NOT NULL DEFAULT false,
 CHECK ((retired AND tenant_id IS NULL AND purpose IS NULL AND fingerprint IS NULL AND fingerprint_key_version IS NULL AND safe_fields IS NULL)
 OR (NOT retired AND tenant_id IS NOT NULL AND purpose IS NOT NULL AND fingerprint IS NOT NULL AND fingerprint_key_version IS NOT NULL AND safe_fields IS NOT NULL)),
 UNIQUE (command_id,tenant_id,purpose)
);

CREATE TABLE identity.commands (
 command_id bytea NOT NULL,
 tenant_id identity.directory_id NOT NULL,
 purpose text COLLATE "C" NOT NULL,
 PRIMARY KEY(tenant_id,purpose,command_id),
 FOREIGN KEY(command_id,tenant_id,purpose)
  REFERENCES identity.identity_command_id_claims(command_id,tenant_id,purpose)
);
`
