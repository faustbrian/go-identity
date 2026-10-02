package postgres

// Prior migrations remain immutable. Terminal storage cannot carry an unknown
// observation, missing classification or a missing/versionless receipt.
const commandTerminalSchemaSQL = `ALTER TABLE identity.commands
 ADD COLUMN result_version integer,
 ADD COLUMN terminal_class text COLLATE "C",
 ADD COLUMN result bytea,
 ADD COLUMN terminal_at timestamptz,
 DROP CONSTRAINT identity_command_lease_shape,
 ADD CONSTRAINT identity_command_lease_shape CHECK (
 num_nonnulls(state,generation,attempt,lease_owner,lease_until,heartbeat_at,created_at,updated_at)=0
 OR (num_nonnulls(state,generation,attempt,lease_owner,lease_until,heartbeat_at,created_at,updated_at)=8
 AND state IN ('pending','committed','aborted') AND octet_length(lease_owner)=16
 AND lease_owner<>decode('00000000000000000000000000000000','hex')
 AND isfinite(lease_until) AND isfinite(heartbeat_at)
 AND isfinite(created_at) AND isfinite(updated_at)
 AND created_at<=heartbeat_at AND heartbeat_at<=updated_at)),
 ADD CONSTRAINT identity_command_terminal_shape CHECK (
 ((state IS NULL OR state='pending') AND num_nonnulls(result_version,terminal_class,result,terminal_at)=0)
 OR (state IS NOT NULL AND state IN ('committed','aborted') AND num_nonnulls(result_version,terminal_class,result,terminal_at)=4
 AND result_version=1 AND octet_length(result) BETWEEN 1 AND 8388608
 AND isfinite(terminal_at) AND created_at<=terminal_at AND terminal_at=updated_at
 AND ((state='committed' AND terminal_class='committed')
 OR (state='aborted' AND terminal_class IN ('denied','conflict','cancelled','deadline-exceeded','dependency-failure')))));
`
