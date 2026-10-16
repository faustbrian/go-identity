package postgres

import (
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// EmailVerificationSigninSession restores the session-owned portion of an exact
// post-verification signin command. It reuses email-possession provenance, not
// password authentication or ordinary magic-link consumption. User must match
// command scope; RecordID names the distinct committed confirmation parent.
// Incomplete or mixed fields deny.
// This is pure structural restoration, not permission to issue: the native
// workflow must prove fresh committed original verification, browser possession,
// original remember choice and all current authority/risk/MFA fences.
func EmailVerificationSigninSession(command identity.Command) (session.Session, error) {
	p, ok := command.Feature()
	if !ok || p.Operation != verificationSigninOperation() || p.Binding.UserID == "" || p.Binding.AnonymousFlowID != "" {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	if _, err := identity.ParseCommandID(p.Binding.RecordID); err != nil || p.Binding.RecordID == string(p.Binding.CommandID) {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	record, err := emailGrantSessionFromFeature(p)
	if err != nil {
		return session.Session{}, err
	}
	spec, _ := record.Bindings()
	metadata, _ := record.MagicLinkAuthentication().Bindings()
	if spec.UserID != p.Binding.UserID || p.Binding.RecordID == string(metadata.RequestCommandID) {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	return record, nil
}

func verificationSigninOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-signin", SchemaID: "email-verification-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
