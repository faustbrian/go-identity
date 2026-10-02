package postgres

const userListSchemaSQL = `CREATE TABLE identity.user_list_snapshots (
 snapshot_id text COLLATE "C" PRIMARY KEY CHECK (snapshot_id ~ '^[A-Za-z0-9_-]{22}$'),
 tenant_id identity.directory_id NOT NULL,
 statuses text[] NOT NULL CHECK (cardinality(statuses) BETWEEN 1 AND 5
   AND statuses <@ ARRAY['active','suspended','banned','anonymized','deleted']::text[]),
 expires_at_ns bigint NOT NULL CHECK (expires_at_ns > 0),
 row_count integer NOT NULL CHECK (row_count BETWEEN 0 AND 100000)
);
CREATE INDEX identity_user_list_retention ON identity.user_list_snapshots(tenant_id,expires_at_ns,snapshot_id);

CREATE TABLE identity.user_list_rows (
 snapshot_id text COLLATE "C" NOT NULL REFERENCES identity.user_list_snapshots(snapshot_id) ON DELETE CASCADE,
 position bigint NOT NULL CHECK (position BETWEEN 1 AND 100000),
 user_id identity.directory_id NOT NULL,
 status text COLLATE "C" NOT NULL CHECK (status IN ('active','suspended','banned','anonymized','deleted')),
 version identity.version NOT NULL,
 PRIMARY KEY (snapshot_id,position),
 UNIQUE (snapshot_id,user_id)
);
`
