package mfapostgres

import (
	"context"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// RequireActionPrimaryFactors fences original known-empty MFA generations for
// selected native username rename, organization transfer/lifecycle and self-only
// passkey enrollment and credential-label update. Read the
// generations using ReadPasswordSigninFactors before freezing command intent;
// bind both action-primary.actor-factor-version and
// action-primary.target-factor-version as uint64 fields. Username rename is
// self-only and requires equal versions, as do archive and restore. Transfer
// requires distinct subjects.
// Missing, changed or enrolled state denies; no factor is initialized and no
// password-only fallback is inferred from session metadata.
//
// Freeze the bounded observations before original intent. In every protected
// preparation stage that exists, and at least in Apply and final precommit
// admission, acquire user/credential locks in canonical subject order before
// calling this guard. No separate preparation transaction is required.
// Factor locks follow canonical subject order and last until Work
// closes. Errors must abort Work. This guard creates no proof, transaction,
// callback, resource or goroutine and never refreshes retained authority.
func RequireActionPrimaryFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, actorVersion, targetVersion uint64) error {
	if ctx == nil || owner == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s, ok := command.Feature()
	b, f, _, err := w.FeatureScope(owner)
	if err != nil || !ok || b != s.Binding {
		return invalidAuthority()
	}
	subjects, err := actionPrimaryFactorSubjects(s, f, actorVersion, targetVersion)
	if err != nil {
		return err
	}
	for _, subject := range subjects {
		if _, err := readKnownEmptyFactors(ctx, w, b, subject.user, subject.version); err != nil {
			return err
		}
	}
	return ctx.Err()
}

type actionPrimaryFactorSubject struct {
	user    identity.UserID
	version uint64
}

func actionPrimaryFactorSubjects(s identity.FeatureCommandSpec, f kernel.FeatureRegistration, actorVersion, targetVersion uint64) ([]actionPrimaryFactorSubject, error) {
	b := s.Binding
	if actorVersion == 0 || targetVersion == 0 || b.ValidateFor(s.Operation) != nil || f.Operation != s.Operation || b.ActorKind != authorization.SubjectUser || b.ActorID == "" || b.UserID == "" {
		return nil, invalidAuthority()
	}
	op := identity.FeatureOperation{Owner: "identity/username", OperationID: "identity.username.update", SchemaID: "identity.username.update.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	descriptor := kernel.ContributorDescriptor{Owner: "identity/username/postgres", ContractID: "identity.username", Version: 1}
	transfer := s.Operation.OperationID == "identity.organization.owner-transfer"
	if transfer {
		op = identity.FeatureOperation{Owner: "organization", OperationID: "identity.organization.owner-transfer", SchemaID: "organization-membership", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
		descriptor = kernel.ContributorDescriptor{Owner: "organization/postgres", ContractID: "organization.membership", Version: 1}
		if string(b.ActorID) == string(b.UserID) {
			return nil, invalidAuthority()
		}
	} else {
		if s.Operation.OperationID == "identity.organization.archive" || s.Operation.OperationID == "identity.organization.restore" {
			op = identity.FeatureOperation{Owner: "organization", OperationID: s.Operation.OperationID, SchemaID: "organization-lifecycle", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			descriptor = kernel.ContributorDescriptor{Owner: "organization/postgres", ContractID: "organization.membership", Version: 1}
		}
		if s.Operation.OperationID == "identity.passkey.register-options" || s.Operation.OperationID == "identity.passkey.register-verify" || s.Operation.OperationID == "identity.passkey.update" {
			op = identity.FeatureOperation{Owner: "passkey", OperationID: s.Operation.OperationID, SchemaID: s.Operation.OperationID + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			descriptor = kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
		}
		if string(b.ActorID) != string(b.UserID) || actorVersion != targetVersion {
			return nil, invalidAuthority()
		}
	}
	if s.Operation != op || f.Contributor != descriptor {
		return nil, invalidAuthority()
	}
	matchedActor, matchedTarget := false, false
	for _, field := range s.Fields {
		switch field.Name {
		case "action-primary.actor-factor-version":
			if matchedActor || field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != actorVersion {
				return nil, invalidAuthority()
			}
			matchedActor = true
		case "action-primary.target-factor-version":
			if matchedTarget || field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != targetVersion {
				return nil, invalidAuthority()
			}
			matchedTarget = true
		default:
			if strings.HasPrefix(field.Name, "action-primary.") {
				return nil, invalidAuthority()
			}
		}
	}
	if !matchedActor || !matchedTarget {
		return nil, invalidAuthority()
	}
	subjects := []actionPrimaryFactorSubject{{identity.UserID(b.ActorID), actorVersion}}
	if transfer {
		subjects = append(subjects, actionPrimaryFactorSubject{b.UserID, targetVersion})
		if subjects[0].user > subjects[1].user {
			subjects[0], subjects[1] = subjects[1], subjects[0]
		}
	}
	return subjects, nil
}
