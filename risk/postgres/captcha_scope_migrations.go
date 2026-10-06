package postgres

import (
	"context"
	"encoding/hex"
	"math"
	"strconv"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// CaptchaScopeMigrationSource adds serialized replay-key retention to an
// installed CaptchaMigrationSource. Allocate Version after that history;
// existing winner, alias and response bytes are preserved. This forward-only
// migration backfills referenced versions and prevents their removal while
// aliases still refer to them. It enables no runtime feature. Load is pure,
// cancellation-aware and concurrent-safe; zero is invalid.
type CaptchaScopeMigrationSource struct {
	Schema  string
	Version migrations.Version
	// Custody supplies the original reviewed retained key configuration for
	// every populated provider scope. Keys cannot be inferred from token-free
	// history. Missing or conflicting versions fail the upgrade atomically;
	// empty is allowed only for an empty CAPTCHA history. Do not mutate this
	// slice concurrently with Load. The migration stores only commitments.
	Custody []risk.CaptchaEvidenceCustody
}

var _ migrations.Source = CaptchaScopeMigrationSource{}

// Load returns one atomic forward upgrade without modifying earlier migrations.
// Invalid allocation returns redacted invalid input; cancellation is preserved.
func (s CaptchaScopeMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) || len(s.Custody) > 32 {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var values []string
	seen := map[string][32]byte{}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
	for _, custody := range s.Custody {
		profile, err := custody.ReplayKeyCustody()
		if err != nil {
			return nil, identity.InvalidInputError{Field: "risk_migration"}
		}
		for _, key := range profile.Keys {
			row := quote(profile.Provider) + "," + quote(profile.Site) + "," + quote(profile.APIProfile) + "," + quote(profile.ConfigurationVersion) + "," + strconv.FormatUint(uint64(key.Version), 10)
			if previous, found := seen[row]; found {
				if previous != key.Commitment {
					return nil, identity.InvalidInputError{Field: "risk_migration"}
				}
				continue
			}
			seen[row] = key.Commitment
			values = append(values, "("+row+",decode('"+hex.EncodeToString(key.Commitment[:])+"','hex'))")
		}
	}
	projection := "SELECT NULL::text AS provider,NULL::text AS site,NULL::text AS api_profile,NULL::text AS configuration_version,NULL::bigint AS key_version,NULL::bytea AS commitment WHERE false"
	if len(values) > 0 {
		projection = "SELECT * FROM (VALUES " + strings.Join(values, ",") + ") AS keys(provider,site,api_profile,configuration_version,key_version,commitment)"
	}
	sql := strings.ReplaceAll(captchaScopeSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	sql = strings.ReplaceAll(sql, "@keys@", projection)
	m, err := migrations.NewMigration(s.Version, "identity_risk_captcha_scope_custody", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

// One row lock per exact provider scope serializes first claims before their
// key sets can diverge. The indexed version relation bounds retention checks
// independently of token history size; alias foreign keys conserve references.
const captchaScopeSchemaSQL = `CREATE TABLE @schema@.captcha_replay_scopes(
 tenant_id text COLLATE "C" NOT NULL CHECK(tenant_id ~ '^[!-~]{1,128}$'),
 provider text COLLATE "C" NOT NULL CHECK(provider IN('recaptcha','turnstile','hcaptcha','captchafox')),
 site text COLLATE "C" NOT NULL CHECK(octet_length(site) BETWEEN 1 AND 512),
 api_profile text COLLATE "C" NOT NULL CHECK(api_profile ~ '^[!-~]{1,128}$'),
 configuration_version text COLLATE "C" NOT NULL CHECK(configuration_version ~ '^[!-~]{1,64}$'),
 PRIMARY KEY(tenant_id,provider,site,api_profile,configuration_version)
);
INSERT INTO @schema@.captcha_replay_scopes
 SELECT DISTINCT tenant_id,provider,site,api_profile,configuration_version FROM @schema@.captcha_replay_winners;
CREATE TABLE @schema@.captcha_replay_scope_keys(
 tenant_id text COLLATE "C" NOT NULL,
 provider text COLLATE "C" NOT NULL,
 site text COLLATE "C" NOT NULL,
 api_profile text COLLATE "C" NOT NULL,
 configuration_version text COLLATE "C" NOT NULL,
 key_version bigint NOT NULL CHECK(key_version BETWEEN 1 AND 4294967295),
 commitment bytea NOT NULL CHECK(octet_length(commitment)=32 AND commitment<>decode(repeat('00',32),'hex')),
 PRIMARY KEY(tenant_id,provider,site,api_profile,configuration_version,key_version),
 FOREIGN KEY(tenant_id,provider,site,api_profile,configuration_version)
 REFERENCES @schema@.captcha_replay_scopes(tenant_id,provider,site,api_profile,configuration_version)
);
INSERT INTO @schema@.captcha_replay_scope_keys
 SELECT DISTINCT a.tenant_id,a.provider,a.site,a.api_profile,a.configuration_version,a.key_version,k.commitment
 FROM @schema@.captcha_replay_alias_versions a
 LEFT JOIN (@keys@) k USING(provider,site,api_profile,configuration_version,key_version);
ALTER TABLE @schema@.captcha_replay_alias_versions ADD CONSTRAINT risk_captcha_referenced_scope_key
 FOREIGN KEY(tenant_id,provider,site,api_profile,configuration_version,key_version)
 REFERENCES @schema@.captcha_replay_scope_keys(tenant_id,provider,site,api_profile,configuration_version,key_version);
`
