package mfapostgres

import (
	"context"
	"sort"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// RequireAdministrativeEmailFactors fences independently known-empty actor and
// target MFA generations for the explicit native administrative removal profile.
// The command must bind both generations and its distinct actor/target scope;
// arbitrary role flags, missing rows or target factor state never establish
// actor eligibility. Enrolled/changed/unknown state denies without downgrade.
// User rows must already be acquired through RequireEmailRemovalSubjects;
// factor locks follow the same canonical subject order until Work closes.
// No proof is created/consumed, state initialized or command scope rewritten.
func RequireAdministrativeEmailFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, actorVersion, targetVersion uint64) error {
	if ctx == nil || owner == nil || actorVersion == 0 || targetVersion == 0 {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s, ok := command.Feature()
	b, f, _, err := w.FeatureScope(owner)
	op := identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.address-remove", SchemaID: "identity.email.address-remove.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if err != nil || !ok || s.Binding != b || s.Operation != op || f.Operation != op || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || b.ActorKind != authorization.SubjectUser || b.ActorID == "" || b.UserID == "" || string(b.ActorID) == string(b.UserID) {
		return invalidAuthority()
	}
	matchedActor, matchedTarget := false, false
	for _, field := range s.Fields {
		switch field.Name {
		case "email.removal.actor-factor-version":
			if matchedActor || field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != actorVersion {
				return invalidAuthority()
			}
			matchedActor = true
		case "email.removal.factor-version":
			if matchedTarget || field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != targetVersion {
				return invalidAuthority()
			}
			matchedTarget = true
		}
	}
	if !matchedActor || !matchedTarget {
		return invalidAuthority()
	}
	users := []struct {
		user    identity.UserID
		version uint64
	}{{identity.UserID(b.ActorID), actorVersion}, {b.UserID, targetVersion}}
	sort.Slice(users, func(i, j int) bool { return users[i].user < users[j].user })
	for _, u := range users {
		if _, err := readKnownEmptyFactors(ctx, w, b, u.user, u.version); err != nil {
			return err
		}
	}
	return ctx.Err()
}
