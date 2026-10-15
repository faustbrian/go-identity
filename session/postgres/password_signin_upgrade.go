package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// PrepareHashUpgrade admits the original prospective signin's directory before
// reserving exclusive predecessor user/credential authority in Work. Call only
// during the registered password owner's original Apply invocation, before any
// shared recipient/credential or material lock. The native owner must already
// have verified the original password, cookie, proof provenance and policy/risk.
// It owns bounded replacement generation and material CAS, not this adapter.
// This method writes no session or credential and starts no transaction. Every
// error must abort the original Work. Success is neither authentication nor
// permission to disclose a bearer, preserve older sessions or renew freshness.
func (e *PasswordSigninEffect) PrepareHashUpgrade(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, recipient kernel.RecipientRecord) error {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 || recipient.Validate() != nil || recipient.Suppressed {
		return session.ErrInvalidSessionCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	_, directory, desired, err := e.hashUpgradeAdmission(w, owner, command)
	f, _ := command.PasswordSigninFeature()
	if err != nil || recipient.Query.TenantID != f.Binding.TenantID || recipient.Query.UserID != f.Binding.UserID || recipient.Query.Eligibility != kernel.RecipientVerified || recipient.User.ID != desired.Credential.UserID || recipient.CredentialAuthorityVersion == ^uint64(0) || desired.CredentialAuthorityVersion != recipient.CredentialAuthorityVersion+1 || desired.UserAuthorityVersion != recipient.UserAuthorityVersion || desired.IdentifierAuthorityVersion != recipient.IdentifierAuthorityVersion || desired.Credential.Version <= 1 {
		return session.ErrInvalidSessionCommand
	}
	bounded, cancel := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer cancel()
	if err := w.RequireActiveDirectoryAuthority(bounded, owner, directory); err != nil {
		return err
	}
	return w.PreparePasswordHashUpgrade(bounded, owner, command, recipient)
}

// ApplyHashUpgrade stages original signin effects only after the kernel's
// reserved upgrade has been applied in this same native invocation. It obtains
// the actual successor from Work, rather than accepting a caller-created
// successor recipient or renewing its observation. The prospective command's
// authentication/reference and independent security epochs must match exactly.
// The registered password owner must supply its unchanged original command,
// have completed material CAS and verified its successor-bound signed proof.
// Pre-auth, policy, family, CSRF, expiry, commit/recovery and pool ownership keep
// Apply's semantics; every error requires abort and output stays provisional.
func (e *PasswordSigninEffect) ApplyHashUpgrade(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, preauth session.PreAuthTransaction) (identity.FeatureReceipt, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	_, _, desired, err := e.hashUpgradeAdmission(w, owner, command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	recipient, actual, err := w.PasswordHashUpgradeSuccessor(owner)
	if err != nil || actual != desired {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	return e.Apply(ctx, w, owner, command, recipient, preauth)
}

func (e *PasswordSigninEffect) hashUpgradeAdmission(w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) (session.Session, kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, error) {
	deny := func() (session.Session, kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, error) {
		return session.Session{}, kernel.DirectoryAuthorityAdmission{}, kernel.CredentialAdmission{}, session.ErrInvalidSessionCommand
	}
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || transition.EventType != "session.created.v1" || transition.BeforeVersion != 0 || transition.AfterVersion != 0 || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) {
		return deny()
	}
	if _, _, _, err := w.FeatureCommandIdentity(owner); err != nil {
		return deny()
	}
	f, ok := command.PasswordSigninFeature()
	if !ok || f.Binding != b || feature.Operation != f.Operation {
		return deny()
	}
	record, err := PasswordSigninSession(command)
	if err != nil {
		return deny()
	}
	s, err := record.Bindings()
	if err != nil {
		return deny()
	}
	selected := b
	selected.UserID, selected.ActorID, selected.ActorKind = s.UserID, identity.ActorID(s.UserID), authorization.SubjectUser
	directory, credential, _, err := sessionAdmissionBindings(e.profile, record, selected, s.SessionID, s.Version)
	if err != nil {
		return deny()
	}
	return record, directory, credential, nil
}
