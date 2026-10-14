package postgres

// New tables preserve structural-only historical users and old writers; no
// defaults are fabricated or backfilled. Typed policy/value admission belongs
// to the owned repository. The trigger prevents ordinary definition mutation,
// not hostile DDL/database owners. No arbitrary attribute index is installed.
const attributeSchemaSQL = `CREATE TABLE identity.attribute_schemas (
 tenant_id identity.directory_id NOT NULL,
 schema_id identity.directory_id NOT NULL,
 schema_version numeric NOT NULL CHECK (schema_version BETWEEN 1 AND 4294967295 AND scale(schema_version)=0),
 definition bytea NOT NULL CHECK (octet_length(definition) BETWEEN 1 AND 524288),
 PRIMARY KEY(tenant_id,schema_id,schema_version)
);
CREATE FUNCTION identity.guard_attribute_schema() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='immutable attribute schema';
END $$;
CREATE TRIGGER identity_attribute_schema_immutable
 BEFORE UPDATE OR DELETE ON identity.attribute_schemas
 FOR EACH ROW EXECUTE FUNCTION identity.guard_attribute_schema();
CREATE TRIGGER identity_attribute_schema_no_truncate
 BEFORE TRUNCATE ON identity.attribute_schemas
 FOR EACH STATEMENT EXECUTE FUNCTION identity.guard_attribute_schema();
CREATE TABLE identity.user_attributes (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 schema_id identity.directory_id NOT NULL,
 schema_version numeric NOT NULL CHECK (schema_version BETWEEN 1 AND 4294967295 AND scale(schema_version)=0),
 encoding_version smallint NOT NULL CHECK (encoding_version=1),
 document bytea NOT NULL CHECK (octet_length(document) BETWEEN 1 AND 524288),
 PRIMARY KEY(tenant_id,user_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id),
 FOREIGN KEY(tenant_id,schema_id,schema_version) REFERENCES identity.attribute_schemas(tenant_id,schema_id,schema_version)
);
`
