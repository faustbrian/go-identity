package postgres

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// PasswordMFAActionSessionGuard admits an original password session for native
// authenticated TOTP step-up or recovery-code regeneration. Existing MFA
// records retain their factor fence; they never enter a single-factor profile.
// This borrowed participant owns no transaction, pool, cache or goroutine.
// Immutable configuration is safe for concurrent independent invocations.
type PasswordMFAActionSessionGuard struct {
	config  Config
	profile IdentifierAdmissionConfig
}

// PasswordMFAActionSessionInput borrows exact command-frozen original session
// custody and separately submitted synchronizer. Keys are the original retained
// lookup and CSRF versions, selected by trusted composition, never request data.
// ValidUntil must match the command's original observation deadline. No field
// supplies fresh factor verification or permission to regenerate recovery codes.
type PasswordMFAActionSessionInput struct {
	Command    identity.Command
	Original   session.Session
	ValidUntil time.Time
	LookupKey  session.DigestKey
	CSRFToken  session.CSRFToken
	CSRFKey    session.CSRFKey
}

// NewPasswordMFAActionSessionGuard freezes an explicit password profile without
// IO. Its current-owner checks reuse the native session reader's original
// password/TOTP and password/recovery mappings, not a fabricated revoke request.
// Unsupported method/organization/passkey dimensions fail closed.
func NewPasswordMFAActionSessionGuard(c Config, p IdentifierAdmissionConfig) (*PasswordMFAActionSessionGuard, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > 5*time.Second || p.Validate() != nil || p.AuthenticationMethod != "password" || p.CredentialKind != identity.CredentialPassword || p.CredentialOwner != "identity/password" {
		return nil, session.ErrInvalidSessionCommand
	}
	c.Schema = strings.Clone(c.Schema)
	p.GlobalAuthorityID, p.PolicyNamespace, p.Audience, p.AuthenticationMethod, p.CredentialOwner = strings.Clone(p.GlobalAuthorityID), strings.Clone(p.PolicyNamespace), strings.Clone(p.Audience), strings.Clone(p.AuthenticationMethod), strings.Clone(p.CredentialOwner)
	return &PasswordMFAActionSessionGuard{config: c, profile: p}, nil
}

func nativeMFAActionBinding(b identity.CommandBinding) bool {
	return b.SchemaVersion == 1 && (b.OperationID == "identity.mfa.totp-verify" && b.SchemaID == "mfa-totp-step-up" || b.OperationID == "identity.mfa.recovery-regenerate" && b.SchemaID == "mfa-recovery-regenerate" || b.OperationID == "identity.mfa.factor-update" && b.SchemaID == "mfa-factor-update")
}

func (g *PasswordMFAActionSessionGuard) admission(original session.Session, b identity.CommandBinding) (revokeRecordAuthority, error) {
	if g == nil || !nativeMFAActionBinding(b) {
		return revokeRecordAuthority{}, identity.ForbiddenError{}
	}
	r := Repository{revokeAdmission: &SingleFactorSessionAdmissionConfig{Verified: &g.profile}, revokeMFAPassword: &g.profile}
	return r.revokeRecordAdmission(original, b)
}

// Check verifies submitted bearer/CSRF possession, original command bindings,
// all current primary owners and the original session/family in the native MFA
// contributor's sole live Apply Work. It preserves the earliest original deadline;
// neither retries nor a fresh database clock renew it. Locks remain owned by
// the coordinator. The participant must propagate every error and abort.
//
// Success is not fresh TOTP proof or regeneration authority. The native MFA
// owner still must verify the actual code, advance replay, persist signed
// evidence, enforce policy/risk and atomically consume the proof on mutation.
// No synchronizer is revealed or consumed by this check.
func (g *PasswordMFAActionSessionGuard) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, input PasswordMFAActionSessionInput) error {
	return g.check(ctx, w, owner, input, true)
}

// AdmitPreparation repeats current-owner admission in the exact registered
// native preparation invocation before counters or encrypted output generation.
// It grants no final mutation permission; Apply must call Check again with the
// unchanged command, and the caller must propagate every denial.
func (g *PasswordMFAActionSessionGuard) AdmitPreparation(ctx context.Context, w kernel.Work, owner kernel.FeaturePreparationContributor, input PasswordMFAActionSessionInput) error {
	return g.check(ctx, w, owner, input, false)
}

// RecheckCommit repeats current authority and expiry checks during the exact
// native owner's final commit callback. That owner must compare the callback's
// command with its retained original command; Apply custody cannot be borrowed
// outside Apply. No new mutation, proof or observation is created here.
func (g *PasswordMFAActionSessionGuard) RecheckCommit(ctx context.Context, w kernel.Work, owner kernel.FeatureCommitContributor, input PasswordMFAActionSessionInput) error {
	return g.check(ctx, w, owner, input, false)
}

func (g *PasswordMFAActionSessionGuard) check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, input PasswordMFAActionSessionInput, apply bool) error {
	if ctx == nil || g == nil {
		return session.ErrInvalidSessionCommand
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b, feature, _, err := w.FeatureScope(owner)
	p, ok := input.Command.Feature()
	if err != nil || !ok || !nativeMFAActionBinding(b) || p.Binding != b || p.Operation != feature.Operation || feature.Operation.Owner != "identity/mfa" || feature.Contributor != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) {
		return identity.ForbiddenError{}
	}
	if apply {
		if err := w.RequireFeatureCommand(ctx, owner, input.Command); err != nil {
			return err
		}
	}
	if err := g.originalInput(input); err != nil {
		return err
	}
	a, err := g.admission(input.Original, b)
	if err != nil || a.credential == nil || a.identifier != nil {
		return identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, g.config.MaximumDuration)
	defer stop()
	if err := w.RequireActiveDirectoryAuthority(bounded, owner, a.directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(bounded, owner, *a.credential); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(bounded, owner, a.policy); err != nil {
		return err
	}
	if a.factor != nil {
		if err := mfapg.RequireTOTPSessionFactor(bounded, w, owner, b.UserID, a.factor.FactorID, mfapg.TOTPSessionFactorState{EnrollmentVersion: a.factor.EnrollmentVersion, AuthorityVersion: a.factor.FactorAuthorityVersion}); err != nil {
			return err
		}
	}
	if err := RequireCSRF(bounded, w, g.config, input.Original, input.CSRFToken, input.CSRFKey); err != nil {
		return err
	}
	now, err := w.DatabaseTime(bounded)
	if err != nil {
		return err
	}
	if !now.Before(input.ValidUntil) || input.ValidUntil.After(now.Add(20*time.Second)) {
		return identity.ForbiddenError{}
	}
	return bounded.Err()
}

func (g *PasswordMFAActionSessionGuard) originalInput(input PasswordMFAActionSessionInput) error {
	p, ok := input.Command.Feature()
	if !ok || !nativeMFAActionBinding(p.Binding) || input.ValidUntil.IsZero() {
		return identity.ForbiddenError{}
	}
	fields := make([]identity.FeatureField, 0, len(p.Fields))
	var deadline string
	for _, f := range p.Fields {
		if strings.HasPrefix(f.Name, originalSessionPrefix) {
			fields = append(fields, f)
		} else if f.Name == "mfa.session-valid-until" {
			if deadline != "" || f.Value.Kind != identity.FeatureText {
				return identity.ForbiddenError{}
			}
			deadline = f.Value.Text
		}
	}
	if deadline != input.ValidUntil.UTC().Format(storedTimeLayout) {
		return identity.ForbiddenError{}
	}
	stored, err := OriginalSessionFromFields(p.Binding.TenantID, p.Binding.UserID, fields)
	if err != nil {
		return identity.ForbiddenError{}
	}
	a, _, ae := encodeRecord(stored)
	z, _, ze := encodeRecord(input.Original)
	if ae != nil || ze != nil || !bytes.Equal(a, z) {
		return identity.ForbiddenError{}
	}
	s, err := input.Original.Bindings()
	borrowed, ok := input.Command.SessionToken()
	if err != nil || !ok {
		return identity.ForbiddenError{}
	}
	token, err := session.ParseToken(borrowed.Token())
	if err != nil {
		return identity.ForbiddenError{}
	}
	digest, err := token.Digest(input.LookupKey, string(s.TenantID))
	if err != nil || digest.KeyVersion != s.Lookup.KeyVersion || subtle.ConstantTimeCompare(digest.Sum[:], s.Lookup.Sum[:]) != 1 {
		return identity.ForbiddenError{}
	}
	if input.Original.CSRFState().Check(session.CSRFBinding{TenantID: s.TenantID, SessionID: s.SessionID, SessionVersion: s.Version}, input.CSRFToken, input.CSRFKey) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

// Format redacts correlated original-session and command configuration.
func (*PasswordMFAActionSessionGuard) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PasswordMFAActionSessionGuard(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (*PasswordMFAActionSessionGuard) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit configuration export.
func (*PasswordMFAActionSessionGuard) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// Format redacts borrowed custody and correlated session metadata.
func (PasswordMFAActionSessionInput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PasswordMFAActionSessionInput(redacted)"))
}

// MarshalJSON rejects implicit custody export.
func (PasswordMFAActionSessionInput) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit custody export.
func (PasswordMFAActionSessionInput) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
