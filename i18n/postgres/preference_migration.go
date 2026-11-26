package postgres

import (
	"context"
	"math"

	"github.com/faustbrian/go-identity/i18n"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// PreferenceMigrationSource installs new owner tables in an unoccupied
// identity_i18n schema. Version is a permanent 1..MaxInt64 allocation in the
// composition's existing go-migrations history. Apply kernel migrations first
// and this additive schema before enabling the native preference profile.
// No existing user data is scanned/backfilled or old table altered. The new
// foreign key briefly locks identity.users; lock_timeout bounds that wait.
// Rollback disables the code and retains personal data for its lifecycle owner;
// there is deliberately no destructive down migration or automatic pruning.
type PreferenceMigrationSource struct{ Version migrations.Version }

// Load performs no IO and preserves cancellation. Schema objects are never
// silently adopted. The existing migration runner owns transaction and history.
func (s PreferenceMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, i18n.PreferenceInputError{}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_i18n_preferences", migrations.TransactionModeDefault, preferenceSchemaSQL, "")
	if err != nil {
		return nil, i18n.PreferenceUnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const preferenceSchemaSQL = `SET LOCAL lock_timeout='5s';
CREATE SCHEMA identity_i18n;
CREATE TABLE identity_i18n.preferences (
 tenant_id identity.directory_id NOT NULL,
 subject_id identity.directory_id NOT NULL,
 locale text COLLATE "C" NOT NULL DEFAULT '' CHECK(octet_length(locale)<=64),
 version numeric NOT NULL DEFAULT 0 CHECK(version>=0 AND version<=18446744073709551615 AND scale(version)=0),
 notice_version numeric NOT NULL DEFAULT 0 CHECK(notice_version>=0 AND notice_version<=18446744073709551615 AND scale(notice_version)=0),
 checkpoint numeric NOT NULL DEFAULT 0 CHECK(checkpoint>=version AND checkpoint<=18446744073709551615 AND scale(checkpoint)=0),
 generation identity.version NOT NULL DEFAULT 1,
 privacy_epoch identity.version NOT NULL DEFAULT 1,
 closed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,subject_id),
 FOREIGN KEY(tenant_id,subject_id) REFERENCES identity.users(tenant_id,user_id),
 CHECK((version=0 AND locale='' AND notice_version=0) OR (version>0 AND locale<>'' AND notice_version>0))
);
CREATE TABLE identity_i18n.preference_updates (
 command_id identity.directory_id PRIMARY KEY,
 tenant_id identity.directory_id NOT NULL,
 subject_id identity.directory_id NOT NULL,
 locale text COLLATE "C" NOT NULL CHECK(octet_length(locale) BETWEEN 1 AND 64),
 version identity.version NOT NULL,
 notice_version identity.version NOT NULL,
 checkpoint identity.version NOT NULL,
 generation identity.version NOT NULL,
 privacy_epoch identity.version NOT NULL,
 command_generation identity.version NOT NULL DEFAULT 1,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 UNIQUE(tenant_id,subject_id,checkpoint),
 FOREIGN KEY(tenant_id,subject_id) REFERENCES identity_i18n.preferences(tenant_id,subject_id),
 CHECK(checkpoint>=version)
);
COMMENT ON TABLE identity_i18n.preferences IS
 'identity/i18n personal-data contributor; closed/generation/privacy_epoch fence all reads and writes. Not a lifecycle acknowledgement';
COMMENT ON TABLE identity_i18n.preference_updates IS
 'Committed same-command locale results and registered preference-update checkpoints, not another journal. Personal payloads require exact lifecycle erasure; do not prune independently of kernel retry retention';
`
