package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// CaptchaMigrationSource installs native CAPTCHA custody in the already-owned
// risk namespace. Install kernel and MigrationSource first; allocate Version
// permanently after every installed migration in the composition's one history.
// This independently selected upgrade requires no phone/counter/lockout tables
// and never rewrites their history. Existing unmanaged objects fail closed.
// Replay winners and aliases have no expiry-based deletion. Evidence payload
// erasure must preserve these independent tombstones and referenced versions.
// Zero is invalid; Load is pure, cancellation-aware and concurrent-safe.
type CaptchaMigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = CaptchaMigrationSource{}

// Load returns one independently owned forward-only atomic migration. This
// creates no issuance or protected-use authority and enables no runtime feature.
// Invalid allocation returns redacted invalid input; cancellation is preserved.
func (s CaptchaMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(captchaSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_captcha_custody", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

// The reservation winner is independent of domain evidence: a rolled-back
// domain transaction cannot erase already-committed replay ownership. Alias
// uniqueness deliberately excludes key version; reused secrets or a digest
// collision cannot create another winner merely by selecting another version.
// A separate immutable version relation conserves all referenced key versions
// even when two retained versions produce the same fingerprint.
const captchaSchemaSQL = `CREATE TABLE @schema@.captcha_replay_winners(
 tenant_id text COLLATE "C" NOT NULL CHECK(tenant_id ~ '^[!-~]{1,128}$'),
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 command_purpose text COLLATE "C" NOT NULL CHECK(command_purpose='identity.risk.captcha-issue'),
 command_fingerprint bytea NOT NULL CHECK(octet_length(command_fingerprint)=32 AND command_fingerprint<>decode(repeat('00',32),'hex')),
 generation numeric NOT NULL CHECK(generation BETWEEN 1 AND 18446744073709551615 AND scale(generation)=0),
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32 AND binding_digest<>decode(repeat('00',32),'hex')),
 intent_digest bytea NOT NULL CHECK(octet_length(intent_digest)=32 AND intent_digest<>decode(repeat('00',32),'hex')),
 configuration_digest bytea NOT NULL CHECK(octet_length(configuration_digest)=32 AND configuration_digest<>decode(repeat('00',32),'hex')),
 provider text COLLATE "C" NOT NULL CHECK(provider IN('recaptcha','turnstile','hcaptcha','captchafox')),
 site text COLLATE "C" NOT NULL CHECK(octet_length(site) BETWEEN 1 AND 512),
 api_profile text COLLATE "C" NOT NULL CHECK(api_profile ~ '^[!-~]{1,128}$'),
 configuration_version text COLLATE "C" NOT NULL CHECK(configuration_version ~ '^[!-~]{1,64}$'),
 reserved_at timestamptz NOT NULL CHECK(isfinite(reserved_at)),
 PRIMARY KEY(tenant_id,command_id),
 UNIQUE(command_id),
 UNIQUE(tenant_id,command_id,provider,site,api_profile,configuration_version),
 FOREIGN KEY(command_id,tenant_id,command_purpose) REFERENCES identity.commands(command_id,tenant_id,purpose)
);
CREATE TABLE @schema@.captcha_replay_aliases(
 tenant_id text COLLATE "C" NOT NULL,
 provider text COLLATE "C" NOT NULL,
 site text COLLATE "C" NOT NULL,
 api_profile text COLLATE "C" NOT NULL,
 configuration_version text COLLATE "C" NOT NULL,
 fingerprint text COLLATE "C" NOT NULL CHECK(fingerprint ~ '^[A-Za-z0-9_-]{43}$'),
 command_id bytea NOT NULL,
 PRIMARY KEY(tenant_id,provider,site,api_profile,configuration_version,fingerprint),
 FOREIGN KEY(tenant_id,command_id,provider,site,api_profile,configuration_version)
 REFERENCES @schema@.captcha_replay_winners(tenant_id,command_id,provider,site,api_profile,configuration_version)
);
CREATE INDEX risk_captcha_alias_owner ON @schema@.captcha_replay_aliases(tenant_id,command_id);
CREATE TABLE @schema@.captcha_replay_alias_versions(
 tenant_id text COLLATE "C" NOT NULL,
 provider text COLLATE "C" NOT NULL,
 site text COLLATE "C" NOT NULL,
 api_profile text COLLATE "C" NOT NULL,
 configuration_version text COLLATE "C" NOT NULL,
 fingerprint text COLLATE "C" NOT NULL,
 key_version bigint NOT NULL CHECK(key_version BETWEEN 1 AND 4294967295),
 PRIMARY KEY(tenant_id,provider,site,api_profile,configuration_version,fingerprint,key_version),
 FOREIGN KEY(tenant_id,provider,site,api_profile,configuration_version,fingerprint)
 REFERENCES @schema@.captcha_replay_aliases(tenant_id,provider,site,api_profile,configuration_version,fingerprint)
);
CREATE INDEX risk_captcha_replay_key_retirement ON @schema@.captcha_replay_alias_versions(key_version);
CREATE TABLE @schema@.captcha_issued_evidence(
 tenant_id text COLLATE "C" NOT NULL,
 command_id bytea NOT NULL,
 command_purpose text COLLATE "C" NOT NULL CHECK(command_purpose='identity.risk.captcha-issue'),
 user_id text COLLATE "C" NOT NULL CHECK(user_id='' OR user_id ~ '^[!-~]{1,128}$'),
 anonymous_flow_id text COLLATE "C" NOT NULL CHECK(anonymous_flow_id='' OR anonymous_flow_id ~ '^[!-~]{1,128}$'),
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32 AND binding_digest<>decode(repeat('00',32),'hex')),
 intent_digest bytea NOT NULL CHECK(octet_length(intent_digest)=32 AND intent_digest<>decode(repeat('00',32),'hex')),
 proof_digest bytea NOT NULL CHECK(octet_length(proof_digest)=32 AND proof_digest<>decode(repeat('00',32),'hex')),
 evidence_digest bytea NOT NULL CHECK(octet_length(evidence_digest)=32 AND evidence_digest<>decode(repeat('00',32),'hex')),
 key_version bigint NOT NULL CHECK(key_version BETWEEN 1 AND 4294967295),
 hostname text COLLATE "C" NOT NULL CHECK(octet_length(hostname)<=253),
 issued_at timestamptz NOT NULL CHECK(isfinite(issued_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
 state text COLLATE "C" NOT NULL CHECK(state IN('issued','reserved','finalized','released','expired','revoked')),
 response_envelope bytea CHECK(octet_length(response_envelope) BETWEEN 100 AND 1024),
 PRIMARY KEY(tenant_id,command_id),
 UNIQUE(command_id),
 UNIQUE(tenant_id,key_version,evidence_digest),
 FOREIGN KEY(tenant_id,command_id) REFERENCES @schema@.captcha_replay_winners(tenant_id,command_id),
 FOREIGN KEY(command_id,tenant_id,command_purpose) REFERENCES identity.commands(command_id,tenant_id,purpose),
 CHECK((user_id='')<>(anonymous_flow_id='')),
 CHECK(expires_at>issued_at AND expires_at-issued_at<=interval '2 minutes'),
 CHECK(state<>'issued' OR response_envelope IS NOT NULL)
);
CREATE INDEX risk_captcha_expiry_order ON @schema@.captcha_issued_evidence(expires_at,tenant_id,command_id);
CREATE INDEX risk_captcha_subject_order ON @schema@.captcha_issued_evidence(tenant_id,user_id,command_id) WHERE user_id<>'';
CREATE INDEX risk_captcha_flow_order ON @schema@.captcha_issued_evidence(tenant_id,anonymous_flow_id,command_id) WHERE anonymous_flow_id<>'';
`
