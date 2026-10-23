package postgres

import (
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// OriginalDeviceGrantAdmission derives the approved human source's exact owner
// expectations while preserving a device-token command's actual client actor
// and anonymous-flow identity. Only the closed native-device-v1 password profile
// is supported. The complete original session must be frozen in the native
// command and matched to its locked approved grant, including source user.
//
// This pure mapping grants no authentication, consent, permission or renewed
// freshness. The native owner must require current directory authority and
// Work.RequireOAuthDeviceGrantSource in its sole transaction, compare current
// client/grant/consent authority and preserve every original deadline. Browser
// approval still uses OriginalSessionAdmission, real possession and CSRF.
// Invalid, foreign or unsupported input returns zero expectations and Forbidden.
// Concurrent immutable use is safe; no IO or resource ownership is introduced.
func OriginalDeviceGrantAdmission(profile IdentifierAdmissionConfig, original session.Session, binding identity.CommandBinding) (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
	deny := func() (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
		return kernel.DirectoryAuthorityAdmission{}, kernel.CredentialAdmission{}, kernel.UserAuthorizationAdmission{}, identity.ForbiddenError{}
	}
	op := identity.FeatureOperation{Owner: "oauth-server/device", OperationID: "identity.oauth-server.device-token", SchemaID: "identity.oauth-server.device-token.native-device-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	s, err := original.Bindings()
	if err != nil || binding.ValidateFor(op) != nil || binding.ActorKind != authorization.SubjectServiceAccount || binding.UserID != "" || binding.AnonymousFlowID != binding.RecordID || s.TenantID != binding.TenantID || profile.CredentialKind != identity.CredentialPassword || profile.CredentialOwner != "identity/password" || profile.AuthenticationMethod != "password" {
		return deny()
	}
	// Only the existing owner's pure scope-key validator sees this local lookup
	// key. No command is constructed or relabeled; the caller's binding, native
	// command identity, audit actor and recovery scope remain client-owned.
	lookup := binding
	lookup.UserID, lookup.ActorID, lookup.ActorKind, lookup.AnonymousFlowID = s.UserID, identity.ActorID(s.UserID), authorization.SubjectUser, ""
	return sessionAdmissionBindings(profile, original, lookup, s.SessionID, s.Version)
}
