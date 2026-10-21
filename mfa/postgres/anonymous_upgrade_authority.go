package mfapostgres

import (
	"context"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

// ReadAnonymousUpgradeFactors reads the permanent target's actual known-empty
// MFA generation before the native owner freezes its upgrade. It is metadata,
// not target authentication, permission or a positive validity lease. Preserve
// the generation in mfa.anonymous-upgrade.factor-version and repeat its exact
// protected fence. Missing/enrolled state denies; it is never initialized here.
// The borrowed primary pool and 1ms..5s budget retain the existing factor owner's
// cancellation/resource semantics; no transaction, retry or goroutine is created.
func ReadAnonymousUpgradeFactors(ctx context.Context, pool *database.Pool, tenant identity.TenantID, user identity.UserID, maximumDuration time.Duration) (mfa.FactorAuthority, error) {
	return readKnownEmptyPrimary(ctx, pool, tenant, user, maximumDuration)
}

// RequireAnonymousUpgradeFactors locks the original permanent target's known-
// empty generation in either exact native issuance admission or protected
// upgrade. Guest state cannot select the target's factors. Call after canonical
// account/session locks and repeat during final checks; the row remains locked
// until the sole coordinator closes Work. Missing, changed, enrolled or corrupt
// authority denies without fallback, initialization or renewed freshness.
func RequireAnonymousUpgradeFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, expectedVersion uint64) (mfa.FactorAuthority, error) {
	if ctx == nil || owner == nil || expectedVersion == 0 {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return mfa.FactorAuthority{}, err
	}
	b, f, _, err := w.FeatureScope(owner)
	if err != nil {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	user, err := anonymousUpgradeFactorSubject(command, b, f, expectedVersion)
	if err != nil {
		return mfa.FactorAuthority{}, err
	}
	if f.Operation.SchemaID == "identity.anonymous.upgrade.prepare.native-v1" {
		if _, ok := owner.(kernel.AnonymousUpgradePreparationContributor); !ok {
			return mfa.FactorAuthority{}, invalidAuthority()
		}
	} else if _, ok := owner.(kernel.AnonymousUpgradeContributor); !ok {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	return readKnownEmptyFactors(ctx, w, b, user, expectedVersion)
}

func anonymousUpgradeFactorSubject(command identity.Command, b identity.CommandBinding, f kernel.FeatureRegistration, expectedVersion uint64) (identity.UserID, error) {
	s, ok := command.Feature()
	if !ok || expectedVersion == 0 || s.Binding != b || s.Operation != f.Operation || b.ValidateFor(s.Operation) != nil || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}) {
		return "", invalidAuthority()
	}
	requirement := identity.FeatureRecordRequired
	schema := "identity.anonymous.upgrade.native-v1"
	if b.OperationID != "identity.anonymous.upgrade" {
		return "", invalidAuthority()
	}
	if s.Operation.SchemaID == "identity.anonymous.upgrade.prepare.native-v1" {
		requirement = identity.FeatureRecordOmitted
		schema = s.Operation.SchemaID
	} else if b.RecordID == string(b.UserID) {
		return "", invalidAuthority()
	}
	if s.Operation != (identity.FeatureOperation{Owner: "identity/anonymous", OperationID: b.OperationID, SchemaID: schema, SchemaVersion: 1, RecordRequirement: requirement}) {
		return "", invalidAuthority()
	}
	matched := false
	for _, field := range s.Fields {
		if field.Name == "mfa.anonymous-upgrade.factor-version" {
			if matched || field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != expectedVersion {
				return "", invalidAuthority()
			}
			matched = true
		} else if strings.HasPrefix(field.Name, "mfa.anonymous-upgrade.") {
			return "", invalidAuthority()
		}
	}
	if !matched {
		return "", invalidAuthority()
	}
	return b.UserID, nil
}
