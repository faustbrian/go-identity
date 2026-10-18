package postgres

import (
	"context"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// PhonePurposeMigrationSource is an opt-in atomic forward suffix admitting
// phone-verification beside the six existing OTP purposes. Allocate Version
// after the selected OTP history. The expected predecessor is the constraint
// installed by MigrationSource; a missing/renamed predecessor fails rather than
// removing an arbitrary constraint. Existing migration bytes and every stored
// digest, scope, counter, timestamp and tombstone remain unchanged. Install this
// before selecting phone issuance; older interpreters still deny unknown purpose.
// Load performs no IO and supports concurrent calls. No down migration exists.
type PhonePurposeMigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = PhonePurposeMigrationSource{}

// Load validates bounded namespace/version and returns owned immutable SQL;
// nil context denies and cancellation propagates without a partial history.
func (s PhonePurposeMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if _, err := (MigrationSource{Schema: s.Schema, Version: s.Version}).Load(ctx); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(phonePurposeSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_otp_phone_purpose", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const phonePurposeSQL = `SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
ALTER TABLE @schema@.challenges
 DROP CONSTRAINT challenges_purpose_check,
 ADD CONSTRAINT challenges_purpose_v2 CHECK(purpose IN('signin','email-verification','password-reset','email-change','mfa','step-up','phone-verification'));
`
