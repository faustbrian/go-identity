package postgres

// Old structural writers need no profile row. Missing name/image mean empty,
// not inferred defaults or a second aggregate authority/version. All future
// profile writes must fence/bump identity.users in the same owned transaction.
const profileSchemaSQL = `CREATE TABLE identity.user_profiles (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 name text NOT NULL CHECK(octet_length(name)<=256),
 image text NOT NULL CHECK(octet_length(image)<=2048),
 PRIMARY KEY(tenant_id,user_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id)
);
`
