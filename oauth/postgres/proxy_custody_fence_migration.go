package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// ProxyCustodyWriteFenceMigrationSource expands one native custody schema.
// Existing binaries and rows remain valid. Apply this before selecting
// writers that send the explicit provider and epoch projection.
type ProxyCustodyWriteFenceMigrationSource struct {
	Schema  string
	Version migrations.Version
	Kind    kernel.OAuthProxyRetirementKind
}

// ProxyCustodyWriteFenceActivationSource enforces the writer contract at
// transaction commit. Apply it only after the expansion and after switching
// all writers of this custody table to the selected live writer. There is no
// downgrade that permits unfenced writers to return.
type ProxyCustodyWriteFenceActivationSource struct {
	Schema  string
	Version migrations.Version
	Kind    kernel.OAuthProxyRetirementKind
}

var (
	_ migrations.Source = ProxyCustodyWriteFenceMigrationSource{}
	_ migrations.Source = ProxyCustodyWriteFenceActivationSource{}
)

// Load builds an independent, forward-only metadata expansion and empty table.
func (s ProxyCustodyWriteFenceMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return proxyCustodyFenceHistory(ctx, s.Schema, s.Version, s.Kind, false)
}

// Load builds the forward-only activation step. Its DDL lock waits for older
// INSERT transactions, and the migration fails rather than activating partially
// if that wait exceeds the lock timeout.
func (s ProxyCustodyWriteFenceActivationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return proxyCustodyFenceHistory(ctx, s.Schema, s.Version, s.Kind, true)
}

func proxyCustodyFenceHistory(ctx context.Context, schema string, version migrations.Version, kind kernel.OAuthProxyRetirementKind, activate bool) ([]migrations.Migration, error) {
	invalid := identity.InvalidInputError{Field: "oauth_proxy_custody_write_fence"}
	if ctx == nil || !providerAuthoritySchema(schema) || version == 0 || version > migrations.Version(math.MaxInt64) {
		return nil, invalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	custody, fence, role := proxyCustodyFenceStorage(kind)
	if role == "" {
		return nil, invalid
	}
	var check string
	if kind == kernel.OAuthProxyRetireProduction {
		check = "OR NEW.fence_provider_id IS DISTINCT FROM NEW.provider_id"
	}
	namespace := rpQuotedSchema(schema) + "."
	name, sql := "identity_oauth_proxy_"+role+"_write_fence", proxyCustodyFenceExpand
	if activate {
		name, sql = name+"_activation", proxyCustodyFenceActivate
	}
	sql = strings.NewReplacer("@custody@", namespace+custody, "@fence@", namespace+fence,
		"@function@", namespace+"enforce_proxy_"+role+"_write_fence", "@check@", check).Replace(sql)
	migration, err := migrations.NewMigration(version, name, migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{migration}, nil
}

func proxyCustodyFenceStorage(kind kernel.OAuthProxyRetirementKind) (custody, fence, role string) {
	switch kind {
	case kernel.OAuthProxyRetireProduction:
		return "proxy_transactions", "proxy_production_write_fences", "production"
	case kernel.OAuthProxyRetirePreview:
		return "proxy_preview_bindings", "proxy_preview_write_fences", "preview"
	default:
		return "", "", ""
	}
}

const proxyCustodyFenceExpand = `SET LOCAL lock_timeout = '5s';
CREATE TABLE @fence@ (
 tenant_id identity.directory_id NOT NULL,
 provider_id text COLLATE "C" NOT NULL CHECK(provider_id ~ '^[a-z0-9_-]{1,128}$'),
 denied_through identity.version NOT NULL,
 PRIMARY KEY(tenant_id,provider_id)
);
ALTER TABLE @custody@
 ADD COLUMN fence_provider_id text COLLATE "C",
 ADD COLUMN fence_provider_epoch numeric;
`

// The insert-only trigger runs in the committing writer transaction after
// native authority reads. A matching local seal holds the exclusive lock.
// Read Committed plus a separate volatile SELECT after the advisory lock
// makes that seal visible even if the writer INSERT preceded it.
const proxyCustodyFenceActivate = `SET LOCAL lock_timeout = '5s';
SELECT fence_provider_id,fence_provider_epoch FROM @custody@ LIMIT 0;
SELECT denied_through FROM @fence@ LIMIT 0;
CREATE FUNCTION @function@() RETURNS trigger
 LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog
AS $fence$
DECLARE
 denied numeric;
BEGIN
 IF current_setting('transaction_isolation') <> 'read committed'
   OR NEW.version <> 1
   OR NEW.fence_provider_id IS NULL OR NEW.fence_provider_id !~ '^[a-z0-9_-]{1,128}$'
   OR NEW.fence_provider_epoch IS NULL OR NEW.fence_provider_epoch < 1
   OR NEW.fence_provider_epoch > 18446744073709551615 OR scale(NEW.fence_provider_epoch) <> 0
   @check@
 THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OAuth proxy custody writer unavailable';
 END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(jsonb_build_array(
   'identity.oauth.proxy.custody-fence.v1', TG_TABLE_SCHEMA, TG_TABLE_NAME,
   NEW.tenant_id::text, NEW.fence_provider_id)::text, 0));
 SELECT f.denied_through INTO denied FROM @fence@ f
 WHERE f.tenant_id=NEW.tenant_id AND f.provider_id=NEW.fence_provider_id;
 IF denied IS NOT NULL AND NEW.fence_provider_epoch <= denied THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='OAuth proxy custody writer unavailable';
 END IF;
 RETURN NULL;
END;
$fence$;
CREATE CONSTRAINT TRIGGER proxy_custody_write_fence AFTER INSERT ON @custody@
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION @function@();
`
