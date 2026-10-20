package reference

import (
	"context"

	authoritypostgres "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	deliverypostgres "github.com/faustbrian/go-identity/delivery/postgres"
	otppostgres "github.com/faustbrian/go-identity/otp/postgres"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	riskpostgres "github.com/faustbrian/go-identity/risk/postgres"
	sessionpostgres "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// MigrationSource returns this selected store graph's immutable upstream-owned
// histories for the existing go-migrations runner. It performs no IO or apply.
// Kernel versions remain 1..9; reference reserves 1000..1011 permanently for
// the velocity authority chain. Existing adapter deployments using other
// allocations are not silently adopted. This partial development profile does
// not implement the complete reference Check/Plan/Apply migration coordinator.
// Selected OTP/delivery appends permanent allocations after that existing
// prefix: kernel 1012..1018 (1019 additionally for selected native TOTP), OTP
// 1100..1103, pre-auth sessions 1200..1201,
// distinct authenticated sessions 1210, delivery 1250..1260 and authorization
// authority 1300. All SQL is supplied by its owner. Shared session schemas
// reuse the same base; unselected profiles contribute no schema.
// Optional consuming Signin appends OTP 1400 and session 1411..1416, plus 1410
// only when its session schema is distinct from the selected session bases.
// Selected original-flow initiation contributes its independent identity_preauth
// history through reference Check/Plan/Apply, not this shared source.
// Selected HTTP rate admission likewise contributes the native rate-limit
// identity_http_rate history through Check/Plan/Apply, not this shared source.
// Audit and outbox independent histories are not part of this shared source;
// their installation remains required before enabling the selected workflow.
func (s StoreSet) MigrationSource() migrations.Source {
	return storeMigrationSource{state: s.state}
}

type storeMigrationSource struct{ state *storeState }

func (s storeMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.state == nil {
		return nil, identity.InvalidInputError{Field: "reference_stores"}
	}
	kernel, err := (identitypostgres.MigrationSource{}).Load(ctx)
	if err != nil {
		return nil, err
	}
	base := riskpostgres.MigrationSource{Schema: s.state.config.Schema, Version: 1000}
	issued := riskpostgres.IssuanceIDMigrationSource{Base: base, Version: 1001}
	reserved := riskpostgres.ReservationMigrationSource{Base: issued, Version: 1002}
	counter := riskpostgres.CounterMigrationSource{Base: reserved, Version: 1003}
	journal := riskpostgres.VelocityMigrationSource{Base: counter, Version: 1004}
	intent := riskpostgres.VelocityIntentMigrationSource{Base: journal, Version: 1005}
	integrity := riskpostgres.VelocityIntegrityMigrationSource{Base: intent, Version: 1006}
	replay := riskpostgres.VelocityReplayMigrationSource{Base: integrity, Version: 1007}
	applied := riskpostgres.VelocityAppliedMigrationSource{Base: replay, Version: 1008}
	coverage := riskpostgres.VelocityCoverageMigrationSource{Base: applied, Version: 1009}
	publication := riskpostgres.VelocityPublicationMigrationSource{Base: coverage, Version: 1010}
	history, err := (riskpostgres.VelocityActivationMigrationSource{Base: publication, Version: 1011}).Load(ctx)
	if err != nil {
		return nil, err
	}
	legacy := append(kernel, history...)
	if s.state.features == nil {
		return legacy, nil
	}
	if err := s.state.features.migrations.validateNamespaces(s.state.config.Schema); err != nil {
		return nil, err
	}
	c := s.state.features.migrations
	if s.state.features.verificationSessionLineage == VerificationBeforeMFA {
		// This lineage installed counter preparation in its forward namespace.
		// Adding magic-link MFA later must not insert legacy shared version1019
		// before an already-applied OTP/session prefix or duplicate that DDL.
		c.magicTOTP = false
	}
	c.emailOTP = s.state.features.email != nil && (s.state.features.email.otpVerification != nil || s.state.features.email.otpChange != nil)
	c.phoneOTP = s.state.features.phone != nil || s.state.features.phoneChange != nil
	return c.load(ctx, fixedMigrationSource(legacy))
}

// This source stores only immutable upstream values, never copied SQL literals.
type fixedMigrationSource []migrations.Migration

func (s fixedMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil {
		return nil, identity.InvalidInputError{Field: "reference_migrations"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]migrations.Migration(nil), s...), nil
}

type featureMigrationConfig struct {
	otpSigninFactors                                        bool
	otpSchema, sessionSchema, global                        string
	authenticatedSchema                                     string
	signinSchema                                            string
	resetSchema                                             string
	passwordSigninSchema                                    string
	magicSessionSchema                                      string
	magicMFAChallenge                                       bool
	magicTOTP                                               bool
	passwordMFA, passwordTOTP                               bool
	passwordRecovery                                        bool
	passwordOTP                                             bool
	emailOTP                                                bool
	phoneOTP                                                bool
	mfaEnrollment                                           bool
	magicSignup                                             bool
	preauthIssue                                            bool
	singleSessionRevocation                                 bool
	tenants                                                 []identity.TenantID
	cancellation, receiptTracking, receipts, reconciliation bool
}

// Different storage owners create their own namespaces. Only the session
// profiles may share a base schema; accepting other overlaps exports DDL that
// can be planned but cannot be installed.
func (c featureMigrationConfig) validateNamespaces(riskSchema string) error {
	if c.otpSchema == riskSchema || c.sessionSchema != "" && (c.sessionSchema == riskSchema || c.sessionSchema == c.otpSchema) || c.authenticatedSchema != "" && (c.authenticatedSchema == riskSchema || c.authenticatedSchema == c.otpSchema) || c.signinSchema != "" && (c.signinSchema == riskSchema || c.signinSchema == c.otpSchema || c.sessionSchema == "") {
		return identity.InvalidInputError{Field: "reference_schema_ownership"}
	}
	return nil
}

func (c featureMigrationConfig) load(ctx context.Context, base migrations.Source) ([]migrations.Migration, error) {
	// Password sessions consume the same permanent native record-format prefix.
	// Selecting that storage history does not construct or advertise OTP signin.
	if c.signinSchema == "" && c.passwordSigninSchema != "" {
		c.signinSchema = c.passwordSigninSchema
	}
	if c.sessionSchema == "" && c.authenticatedSchema == "" {
		return nil, identity.InvalidInputError{Field: "reference_session_migrations"}
	}
	prepared := identitypostgres.PreparationMigrationSource{Base: base, Version: 1012}
	admitted := identitypostgres.AdmissionPreparationMigrationSource{Base: prepared, Version: 1013}
	status := identitypostgres.StatusMigrationSource{Base: admitted, Version: 1014}
	credentials := identitypostgres.CredentialMigrationSource{Base: status, Version: 1015}
	directory := identitypostgres.DirectoryAuthorityMigrationSource{Base: credentials, Version: 1016, GlobalAuthorityID: c.global, TenantIDs: c.tenants}
	keyed := identitypostgres.RequestKeyMigrationSource{Base: directory, Version: 1017}
	var complete migrations.Source = identitypostgres.RequestKeyPreparationMigrationSource{Base: keyed, Version: 1018}
	if c.magicTOTP {
		complete = identitypostgres.CounterPreparationMigrationSource{Base: complete, Version: 1019}
	}
	history, err := complete.Load(ctx)
	if err != nil {
		return nil, err
	}
	sources := []migrations.Source{
		otppostgres.MigrationSource{Schema: c.otpSchema, Version: 1100},
		otppostgres.LockoutMigrationSource{Schema: c.otpSchema, Version: 1101},
		otppostgres.SendFamilyMigrationSource{Schema: c.otpSchema, Version: 1102},
		otppostgres.IssuanceMigrationSource{Schema: c.otpSchema, Version: 1103},
	}
	if c.sessionSchema != "" {
		sources = append(sources, sessionpostgres.MigrationSource{Schema: c.sessionSchema, Version: 1200}, sessionpostgres.PreAuthMigrationSource{Schema: c.sessionSchema, Version: 1201})
	}
	if c.authenticatedSchema != "" && c.authenticatedSchema != c.sessionSchema {
		sources = append(sources, sessionpostgres.MigrationSource{Schema: c.authenticatedSchema, Version: 1210})
	}
	for _, source := range sources {
		next, err := source.Load(ctx)
		if err != nil {
			return nil, err
		}
		history = append(history, next...)
	}
	deliverySource := deliverypostgres.MigrationSource{Base: fixedMigrationSource(history), Version: 1250, WorkerVersion: 1251, PolicyVersion: 1252, KeyedVersion: 1253, StateVersion: 1254}
	if c.cancellation {
		deliverySource.CancellationVersion = 1255
	}
	if c.receiptTracking || c.receipts || c.reconciliation {
		deliverySource.ReceiptVersion = 1256
	}
	if c.receipts {
		deliverySource.ReceiptCommandVersion = 1257
	}
	if c.reconciliation {
		deliverySource.ReconciliationVersion = 1258
		deliverySource.ReconciliationCommandVersion = 1259
		deliverySource.ReconciliationQueryVersion = 1260
	}
	history, err = deliverySource.Load(ctx)
	if err != nil {
		return nil, err
	}
	// The authority owner exposes a version-neutral SQL value as well as its
	// older migrations-module adapter. Adapt that value, not a copied schema.
	authority, err := authoritypostgres.AuthoritySchemaMigration(1300)
	if err != nil {
		return nil, err
	}
	next, err := migrations.NewMigration(migrations.Version(authority.Version), authority.Name, migrations.TransactionModeDefault, authority.Up, authority.Down)
	if err != nil {
		return nil, err
	}
	history = append(history, next)
	if c.signinSchema != "" || c.emailOTP || c.phoneOTP {
		next, err := (otppostgres.ConsumingMigrationSource{Schema: c.otpSchema, Version: 1400}).Load(ctx)
		if err != nil {
			return nil, err
		}
		history = append(history, next...)
	}
	if c.signinSchema == "" {
		return history, nil
	}
	// Existing Send-only histories end at 1300. Append this profile as a suffix
	// so enabling it never creates a gap before an already-applied migration.
	baseVersion := migrations.Version(1410)
	if c.signinSchema == c.sessionSchema {
		baseVersion = 1200
	} else if c.signinSchema == c.authenticatedSchema {
		baseVersion = 1210
	}
	owned, err := (sessionpostgres.IssueMigrationSource{Base: sessionpostgres.RevocationMigrationSource{Base: sessionpostgres.MigrationSource{Schema: c.signinSchema, Version: baseVersion}, Version: 1411}, Version: 1412}).Load(ctx)
	if err != nil {
		return nil, err
	}
	if baseVersion != 1410 {
		owned = owned[1:] // The exact upstream base is already selected above.
	}
	for _, source := range []migrations.Source{
		fixedMigrationSource(owned),
		sessionpostgres.PreAuthReleaseMigrationSource{Schema: c.sessionSchema, Version: 1413},
		sessionpostgres.CSRFMigrationSource{Schema: c.signinSchema, Version: 1414},
		sessionpostgres.OTPMigrationSource{Schema: c.signinSchema, Version: 1415},
		sessionpostgres.OTPIssueMigrationSource{Schema: c.signinSchema, Version: 1416},
	} {
		next, err := source.Load(ctx)
		if err != nil {
			return nil, err
		}
		history = append(history, next...)
	}
	if c.singleSessionRevocation {
		owned, err := (sessionpostgres.RevokeOneMigrationSource{Base: sessionpostgres.RevocationMigrationSource{Base: sessionpostgres.MigrationSource{Schema: c.signinSchema, Version: baseVersion}, Version: 1411}, Version: 1417}).Load(ctx)
		if err != nil {
			return nil, err
		}
		// Base and family histories retain their existing allocation/checksums.
		// Only the separately selected single-session receipt is appended.
		history = append(history, owned[len(owned)-1])
	}
	return history, nil
}
