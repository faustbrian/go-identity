package postgres

// Foundation-only rows retain NULL metadata: their prior execution outcome is
// not knowable from migration history. The coordinator must fail closed on them
// until authoritative reconciliation; migration must not fabricate ownership.
// Only pending storage is enabled here. Terminal receipts are a later forward
// migration, not NULL results masquerading as committed or aborted commands.
const commandLeaseSchemaSQL = `ALTER TABLE identity.commands
 ADD COLUMN state text COLLATE "C",
 ADD COLUMN generation identity.version,
 ADD COLUMN attempt identity.version,
 ADD COLUMN lease_owner bytea,
 ADD COLUMN lease_until timestamptz,
 ADD COLUMN heartbeat_at timestamptz,
 ADD COLUMN created_at timestamptz,
 ADD COLUMN updated_at timestamptz,
 ADD CONSTRAINT identity_command_lease_shape CHECK (
 num_nonnulls(state,generation,attempt,lease_owner,lease_until,heartbeat_at,created_at,updated_at)=0
 OR (num_nonnulls(state,generation,attempt,lease_owner,lease_until,heartbeat_at,created_at,updated_at)=8
 AND state='pending' AND octet_length(lease_owner)=16
 AND lease_owner<>decode('00000000000000000000000000000000','hex')
 AND isfinite(lease_until) AND isfinite(heartbeat_at)
 AND isfinite(created_at) AND isfinite(updated_at)
 AND created_at<=heartbeat_at AND heartbeat_at<=updated_at)),
 ADD CONSTRAINT identity_command_lease_attempt CHECK (attempt>=generation);

CREATE INDEX identity_commands_pending_lease
 ON identity.commands(lease_until,tenant_id,purpose,command_id)
 WHERE state='pending';
`
