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

// ReadPhoneFactors reads actual known-empty factor authority before the native
// existing-account phone owner freezes its original command. It is preliminary
// metadata, not authentication, enrollment or permission to issue/consume OTP.
// Retain its positive generation as the uint64 phone.factor-version command
// field and fence it using RequirePhoneFactors in protected admission, mutation
// and final checks. Missing, enrolled or corrupt state denies without initializing
// authority. The pool is borrowed; maximumDuration is explicit, 1ms..5s, and
// earlier cancellation wins. No transaction, retry or goroutine is created.
func ReadPhoneFactors(ctx context.Context, pool *database.Pool, tenant identity.TenantID, user identity.UserID, maximumDuration time.Duration) (mfa.FactorAuthority, error) {
	return readKnownEmptyPrimary(ctx, pool, tenant, user, maximumDuration)
}

// RequirePhoneFactors fences the original known-empty factor generation for the
// exact registered self-user native phone enrollment, replacement or removal
// owner, including replacement's non-attaching send schema.
// The command must retain phone.factor-version as uint64 equal to expectedVersion;
// unknown phone.factor-* fields deny. Acquire original account/session locks
// first and repeat this check in every protected admission phase and final
// precommit check. The actual factor row stays locked until coordinator Work
// closes. Missing, changed, enrolled or corrupt authority denies; no row is
// initialized, original validity renewed, or weaker fallback selected. This
// grants no phone/OTP mutation or authentication proof. Errors must abort Work;
// the function owns no transaction, retry, callback, resource or goroutine.
func RequirePhoneFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, expectedVersion uint64) (mfa.FactorAuthority, error) {
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
	user, err := phoneFactorSubject(command, b, f, expectedVersion)
	if err != nil {
		return mfa.FactorAuthority{}, err
	}
	return readKnownEmptyFactors(ctx, w, b, user, expectedVersion)
}

func phoneFactorSubject(command identity.Command, b identity.CommandBinding, f kernel.FeatureRegistration, expectedVersion uint64) (identity.UserID, error) {
	s, ok := command.Feature()
	if !ok || expectedVersion == 0 || s.Binding != b || b.ValidateFor(s.Operation) != nil || f.Operation != s.Operation ||
		b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) {
		return "", invalidAuthority()
	}
	if f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}) {
		return "", invalidAuthority()
	}
	switch s.Operation.OperationID {
	case "identity.phone.send-verification", "identity.phone.verify", "identity.phone.remove", "identity.phone.update":
	default:
		return "", invalidAuthority()
	}
	op := identity.FeatureOperation{Owner: "identity/phone", OperationID: s.Operation.OperationID, SchemaID: s.Operation.OperationID + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	// Replacement sends deliberately have no pending-identifier attachment.
	// Admit only that exact profile; arbitrary send aliases remain unsupported.
	if op.OperationID == "identity.phone.send-verification" && s.Operation.SchemaID == "identity.phone.send-verification.change.native-v1" {
		op.SchemaID = s.Operation.SchemaID
	}
	if s.Operation != op {
		return "", invalidAuthority()
	}
	matched := false
	for _, field := range s.Fields {
		if field.Name == "phone.factor-version" {
			if matched || field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != expectedVersion {
				return "", invalidAuthority()
			}
			matched = true
		} else if strings.HasPrefix(field.Name, "phone.factor-") {
			return "", invalidAuthority()
		}
	}
	if !matched {
		return "", invalidAuthority()
	}
	return b.UserID, nil
}
