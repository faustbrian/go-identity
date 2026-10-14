package postgres

// A constant initial authority version preserves old structural writers and
// existing users without inventing a value during reads. Identifier and
// verification projections share one row so consistency is database-enforced.
const identifierSchemaSQL = `ALTER TABLE identity.users
 ADD COLUMN identifier_version numeric NOT NULL DEFAULT 1
 CHECK (identifier_version >= 1 AND identifier_version <= 18446744073709551615
        AND scale(identifier_version) = 0);

CREATE DOMAIN identity.identifier_value AS text COLLATE "C"
 CHECK (octet_length(VALUE) BETWEEN 1 AND 512
        AND VALUE !~ U&'[\0001-\001F\007F-\009F]');

CREATE TABLE identity.identifiers (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 identifier_id identity.directory_id NOT NULL,
 kind text COLLATE "C" NOT NULL
  CHECK (kind IN ('email','phone','username','provider-subject')),
 canonical_value identity.identifier_value NOT NULL,
 display_value text COLLATE "C" NOT NULL DEFAULT ''
  CHECK (octet_length(display_value) <= 512
         AND display_value !~ U&'[\0001-\001F\007F-\009F]'),
 verified boolean NOT NULL DEFAULT false,
 is_primary boolean NOT NULL DEFAULT false,
 version identity.version NOT NULL,
 verification_state smallint NOT NULL CHECK (verification_state BETWEEN 1 AND 3),
 verification_version identity.version NOT NULL,
 verified_at timestamptz,
 PRIMARY KEY (tenant_id,user_id,identifier_id),
 UNIQUE (tenant_id,identifier_id),
 UNIQUE (tenant_id,kind,canonical_value),
 FOREIGN KEY (tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id),
 CHECK (verified = (verification_state = 2)),
 CHECK (NOT is_primary OR verified),
 CHECK (verification_state <> 1 OR verified_at IS NULL),
 CHECK (verification_state <> 2 OR verified_at IS NOT NULL),
 CHECK (verified_at IS NULL OR (verified_at >= timestamptz '0001-01-01 00:00:00+00'
        AND verified_at < timestamptz '10000-01-01 00:00:00+00'))
);

CREATE UNIQUE INDEX identity_identifier_primary_kind
 ON identity.identifiers(tenant_id,user_id,kind) WHERE is_primary;
`
