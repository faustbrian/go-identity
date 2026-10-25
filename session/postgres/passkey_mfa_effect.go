package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// MFAPasskeyTOTPCompletionEffect selects original passkey plus recorded native
// TOTP completion. It retains the existing session mutation/recovery owner;
// it is not a factor verifier, assertion authenticator or public login service.
// No pool, transaction, callback, goroutine or borrowed Work is retained.
type MFAPasskeyTOTPCompletionEffect struct{ native *MFATOTPCompletionEffect }

// NewMFAPasskeyTOTPCompletionEffect freezes an explicit RP/mapping selection.
// The actual native factor owner must authenticate original assertion/browser/
// child, current policy, directory and credential, and lock mapping authority
// before factor locks. Apply repeats eligibility checks but cannot manufacture
// these proofs. Install the selected MFA/session histories before use. The
// mapping owner is borrowed and must outlive calls; construction performs no IO.
func NewMFAPasskeyTOTPCompletionEffect(c Config, p MFAPasskeySessionAdmission) (*MFAPasskeyTOTPCompletionEffect, error) {
	if !p.Profile.valid() || nilIssueDependency(p.Authority) {
		return nil, session.ErrInvalidSessionCommand
	}
	profile := freezePasskeyProfile(p.Profile)
	common, err := NewMFATOTPCompletionEffect(c, MagicLinkAdmissionConfig{GlobalAuthorityID: profile.GlobalAuthorityID, PolicyNamespace: profile.PolicyNamespace, Audience: profile.Audience})
	if err != nil {
		return nil, err
	}
	common.passkey = &mfaPasskeySessionSelection{profile: profile, authority: p.Authority}
	return &MFAPasskeyTOTPCompletionEffect{native: common}, nil
}

// Apply persists only the unchanged passkey/TOTP session whose actual native
// replay/continuation completion was recorded on this same live Work. Projected
// metadata or a foreign/returned handle cannot substitute. Original primary
// time, expiry and Remember are immutable; no recipient/email proof is assumed.
// All errors abort the sole transaction with child/factor/session/audit effects.
func (e *MFAPasskeyTOTPCompletionEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command, completed mfapg.LockedTOTPCompletion) (identity.FeatureReceipt, error) {
	if e == nil || e.native == nil {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	return e.native.Apply(ctx, w, owner, command, kernel.RecipientRecord{}, completed)
}

// Check must run in the same original owner's CheckFeatureCommit after later
// audit/outbox waits. It repeats current directory/credential/policy/RP admission,
// exact stored session and original proof freshness. Locks taken by the actual
// factor completion remain held; it never repeats factor comparison/consumption,
// adopts newer epochs or renews a credential or evidence deadline.
func (e *MFAPasskeyTOTPCompletionEffect) Check(ctx context.Context, w kernel.Work, owner kernel.MFACompletionContributor, command identity.Command) error {
	if ctx == nil || e == nil || e.native == nil || e.native.passkey == nil {
		return session.ErrInvalidSessionCommand
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b, feature, transition, err := w.FeatureScope(owner)
	spec, ok := command.Feature()
	if err != nil || !ok || spec.Binding != b || feature.Operation != mfaTOTPCompletionSessionOperation() || spec.Operation != feature.Operation || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) || transition != (kernel.LifecyclePlan{EventType: "session.created.v1"}) {
		return session.ErrInvalidSessionCommand
	}
	record, err := MFATOTPCompletionSession(command)
	if err != nil {
		return err
	}
	s, _ := record.Bindings()
	selected := b
	selected.UserID, selected.ActorID, selected.ActorKind = s.UserID, identity.ActorID(s.UserID), authorization.SubjectUser
	directory, credential, policy, err := passkeyMFASessionAdmission(e.native.passkey.profile, record, selected)
	if err != nil {
		return err
	}
	bounded, stop := context.WithTimeout(ctx, e.native.config.MaximumDuration)
	defer stop()
	if err := w.RequireActiveDirectoryAuthority(bounded, owner, directory); err != nil {
		return err
	}
	if _, err := w.RequireMFAPasskeyCredential(bounded, owner, credential); err != nil {
		return err
	}
	if err := authority.RequireAuthority(bounded, w, policy.Scope, policy.Version, e.native.config.MaximumDuration); err != nil {
		if errors.Is(err, authority.ErrAuthorityDenied) {
			return identity.ForbiddenError{}
		}
		return readError(bounded, err)
	}
	if err := e.native.passkey.authority.RequireMFAPasskeySession(bounded, w, owner, e.native.passkey.profile.RPNamespace, record); err != nil {
		return err
	}
	if err := RequireSession(bounded, w, e.native.config, record); err != nil {
		return err
	}
	return e.native.requireIssueTime(bounded, w, record)
}

// Recover contributes only the original retained session-issuance vote in the
// exact registered owner's recovery Work. It never repeats factor verification,
// authenticates a session, reconstructs credentials or renews a challenge.
func (e *MFAPasskeyTOTPCompletionEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.MFACompletionContributor) (kernel.RecoveryStatus, error) {
	if e == nil || e.native == nil {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	return e.native.Recover(ctx, w, owner)
}

// Format redacts borrowed authority and correlated deployment configuration.
func (*MFAPasskeyTOTPCompletionEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MFAPasskeyTOTPCompletionEffect(redacted)"))
}

// MarshalJSON rejects implicit correlated configuration disclosure.
func (*MFAPasskeyTOTPCompletionEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit configuration export and map-key disclosure.
func (*MFAPasskeyTOTPCompletionEffect) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
