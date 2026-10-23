package reference

import (
	"fmt"
	"io"
	"slices"

	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	anonymouspg "github.com/faustbrian/go-identity/anonymous/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// AnonymousConfiguration selects native guest creation/read and optionally
// self-deletion, upgrade and trusted abandoned-guest maintenance. It enables no
// HTTP or scheduler. Cleanup is independent of Deletion; its Clock must be nil
// for this graph's system-clock injection. Signin.Risk.Evaluation must be
// zero for injection of this graph's counted owner. PreAuth selects its exact
// original-flow initiation; lookup key comes from Signin.FlowKeys. Deletion
// uses the same repository/session/profile/CSRF policy as issuance and its real
// protected counter owner. No application domain stores are accepted.
type AnonymousConfiguration struct {
	Signin     anonymouspg.SigninConfig
	Validation session.ServiceConfig
	PreAuth    PasswordPreAuthConfiguration
	Deletion   *anonymouspg.DeletionConfig
	Upgrade    *AnonymousUpgradeConfiguration
	Cleanup    *anonymouspg.CleanupConfig
}

// AnonymousUpgradeConfiguration selects the finite existing-password target
// without resource transfers. Primary must name identity.anonymous.upgrade and
// use cookie custody with CSRFKeys absent; this graph injects its existing
// password verification/target session owners and synchronizers. ProofAudience
// is the selected target session audience in this profile. Capability custody
// retains the native issuer/preparation keys for original-command recovery.
// Issuer and CSRF must match the selected permanent cookie policy and retained
// read/signout keys; incompatible replacement credentials fail at composition.
type AnonymousUpgradeConfiguration struct {
	Primary               passwordpg.ActionPrimaryConfig
	ProofAudience         string
	Issuer                session.IssuerConfig
	CSRF                  session.CSRFKey
	Capability            capabilitypg.IssuerConfig
	CapabilityPreparation capabilitypg.IssuancePreparationConfig
}

func (AnonymousConfiguration) Format(s fmt.State, _ rune) {
	io.WriteString(s, "reference.AnonymousConfiguration(redacted)")
}
func (AnonymousConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (AnonymousConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (AnonymousUpgradeConfiguration) Format(s fmt.State, _ rune) {
	io.WriteString(s, "reference.AnonymousUpgradeConfiguration(redacted)")
}
func (AnonymousUpgradeConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (AnonymousUpgradeConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

type anonymousState struct {
	signin        *anonymouspg.SigninService
	reader        *session.AnonymousSessionService
	deletion      *anonymouspg.DeletionService
	upgrade       *anonymouspg.UpgradeService
	cleanup       *anonymouspg.CleanupService
	subjects      *anonymouspg.Repository
	preauth       *session.PreAuthIssuer
	repository    anonymouspg.Config
	sessions      sessionpg.Config
	profile       sessionpg.AnonymousAdmissionConfig
	cookie        session.CookiePolicy
	preauthConfig PasswordPreAuthConfiguration
	policy        string
	version       uint64
	reasons       []string
}

func composeAnonymous(c StoreConfiguration, d ReferenceDependencies, evaluation risk.Evaluator, proofs *passwordVerificationState) (*anonymousState, error) {
	if c.Anonymous == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_anonymous"}
	n := *c.Anonymous
	p, s := n.PreAuth, n.Signin
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || d.PostgreSQL == nil || c.OTP == nil || s.Risk.Evaluation != (risk.Evaluator{}) || s.Coordinator.QueryPolicy == nil || s.Coordinator.AdmissionPolicy == nil || s.Coordinator.AdmissionPolicy.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(s.Coordinator.AdmissionPolicy.Authorization, c.OTP.RequestKeys.Policy.Authorization) || !sameServerAuthorization(s.Coordinator.QueryPolicy.Authorization, c.OTP.RequestKeys.Policy.Authorization) || s.Profile.GlobalAuthorityID != c.OTP.Store.GlobalAuthorityID || s.Repository.MaximumDuration > c.OTP.Timeout || s.Sessions.MaximumDuration > c.OTP.Timeout || uint64(p.FlowKeyIndex) >= uint64(len(s.FlowKeys)) || !slices.Contains(s.Origins, p.Origin) || !slices.Contains(s.CallbackURLs, p.CallbackURL) {
		return nil, invalid
	}
	s.Risk.Evaluation = evaluation
	signin, err := anonymouspg.NewSigninService(d.PostgreSQL, s, keys)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_anonymous_signin"}
	}
	validation := n.Validation
	if validation.Clock != nil || validation.Audience != s.Profile.Audience {
		return nil, invalid
	}
	validation.Clock = clock.System{}
	readProfile := SessionConfiguration{}
	readProfile.Native.Validation = validation
	if n.Deletion != nil {
		readProfile.CSRFKeys = n.Deletion.CSRFKeys
	}
	if !sessionKeysMatch(readProfile, s.Issuer.LookupKey, s.CSRF) {
		return nil, invalid
	}
	// This reference profile reuses its installed consuming-session base. A
	// separately named native anonymous store remains available directly, but
	// cannot be silently treated as an already migrated reference namespace.
	if c.PasswordSignin != nil {
		if s.Sessions != c.PasswordSignin.Native.Session {
			return nil, invalid
		}
	} else if c.OTP.Signin == nil || s.Sessions != c.OTP.Signin.Session {
		return nil, invalid
	}
	if n.Deletion != nil {
		del := *n.Deletion
		if del.Repository != s.Repository || del.Sessions != s.Sessions || del.Profile != s.Profile || del.Validation.Clock != nil || del.Validation.Profile != 0 || del.Validation.Audience != "" || del.Validation.MaximumDuration != 0 || del.Validation.ClockUncertainty != 0 || len(del.Validation.LookupKeys) != 0 || del.Risk.Schema != c.Velocity.Schema || del.Risk.CommandCounters == nil || del.Risk.CommandCounters.Policy != c.Velocity.Native.Policy || del.Risk.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion || del.RequestKeys.Policy.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(del.RequestKeys.Policy.Authorization, c.OTP.RequestKeys.Policy.Authorization) {
			return nil, invalid
		}
	}
	reader, err := anonymouspg.NewSessionService(d.PostgreSQL, anonymouspg.SessionServiceConfig{Repository: s.Repository, Sessions: s.Sessions, Profile: s.Profile, Validation: validation})
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_anonymous_reader"}
	}
	repository, err := anonymouspg.NewRepository(d.PostgreSQL, s.Repository)
	if err != nil {
		return nil, err
	}
	a := &anonymousState{signin: signin, reader: reader, subjects: repository, repository: s.Repository, sessions: s.Sessions, profile: s.Profile, cookie: s.Issuer.Cookie, preauthConfig: p, policy: s.PolicyID, version: s.Coordinator.AdmissionPolicy.PolicyVersion}
	if n.Cleanup != nil {
		cleanup := *n.Cleanup
		if cleanup.Clock != nil || cleanup.Repository != s.Repository || cleanup.Sessions != s.Sessions || cleanup.GlobalAuthorityID != s.Profile.GlobalAuthorityID || cleanup.Coordinator.MaximumDuration > c.OTP.Timeout || cleanup.RequestKeys.Policy.PolicyVersion != a.version || cleanup.Coordinator.AdmissionPolicy == nil || cleanup.Coordinator.QueryPolicy == nil || cleanup.Coordinator.AdmissionPolicy.PolicyVersion != a.version || cleanup.Coordinator.QueryPolicy.PolicyVersion != a.version || !sameServerAuthorization(cleanup.RequestKeys.Policy.Authorization, c.OTP.RequestKeys.Policy.Authorization) || !sameServerAuthorization(cleanup.Coordinator.AdmissionPolicy.Authorization, c.OTP.RequestKeys.Policy.Authorization) || !sameServerAuthorization(cleanup.Coordinator.QueryPolicy.Authorization, c.OTP.RequestKeys.Policy.Authorization) {
			return nil, invalid
		}
		cleanup.Clock = clock.System{}
		a.cleanup, err = anonymouspg.NewCleanupService(d.PostgreSQL, cleanup, keys)
		if err != nil {
			return nil, identity.InvalidInputError{Field: "reference_anonymous_cleanup"}
		}
	}
	executor, err := sessionpg.NewPreAuthIssueExecutor(d.PostgreSQL, sessionpg.PreAuthIssueExecutorConfig{Repository: s.Sessions, Coordinator: s.Coordinator, Authorization: s.Coordinator.QueryPolicy.Authorization, Clock: clock.System{}, ActorID: p.ActorID, Action: "identity.anonymous.signin", Origin: p.Origin, CallbackURL: p.CallbackURL, PolicyID: s.PolicyID, PolicyVersion: a.version, AuditRetentionVersion: p.AuditRetentionVersion})
	if err != nil {
		return nil, err
	}
	a.preauth, err = session.NewPreAuthIssuer(executor, session.PreAuthIssuerConfig{ActorID: p.ActorID, Action: "identity.anonymous.signin", Origin: p.Origin, CallbackURL: p.CallbackURL, PolicyID: s.PolicyID, PolicyVersion: a.version, Clock: clock.System{}, MaximumDuration: s.Sessions.MaximumDuration, FlowTTL: p.FlowTTL, LookupKey: s.FlowKeys[p.FlowKeyIndex], TokenSize: p.TokenSize, Cookie: p.Cookie})
	if err != nil {
		return nil, err
	}
	if n.Deletion != nil {
		del := *n.Deletion
		del.Validation = validation
		a.deletion, err = anonymouspg.NewDeletionService(d.PostgreSQL, del, keys)
		if err != nil {
			return nil, identity.InvalidInputError{Field: "reference_anonymous_deletion"}
		}
		a.reasons = slices.Clone(del.Reasons)
		if n.Upgrade != nil {
			u := *n.Upgrade
			if c.PasswordSignin == nil || c.PasswordVerification == nil || c.Session == nil || proofs == nil || proofs.native == nil || proofs.proofs == nil || u.Primary.Action != "identity.anonymous.upgrade" || u.Primary.Transport != session.CredentialCookie || len(u.Primary.CSRFKeys) != 0 || u.ProofAudience != c.PasswordSignin.Native.Profile.Audience || u.Primary.Audience != u.ProofAudience || !sessionIssuanceMatches(*c.Session, u.Issuer, u.CSRF) {
				return nil, invalid
			}
			u.Primary.CSRFKeys = slices.Clone(c.PasswordVerification.CSRFKeys)
			primary, err := passwordpg.NewActionPrimarySource(proofs.native, u.Primary)
			if err != nil {
				return nil, err
			}
			target := sessionpg.SessionServiceConfig{Repository: c.Session.Native.Execution.Repository, Profile: c.PasswordSignin.Native.Profile, Validation: c.Session.Native.Validation}
			target.Validation.Clock = c.Session.Native.Execution.Clock
			a.upgrade, err = anonymouspg.NewUpgradeService(d.PostgreSQL, anonymouspg.UpgradeConfig{Guest: del, Primary: primary, Target: target, TargetCSRFKeys: c.PasswordVerification.CSRFKeys, ProofAudience: u.ProofAudience, Issuer: u.Issuer, CSRF: u.CSRF, Capability: u.Capability, CapabilityPreparation: u.CapabilityPreparation}, keys)
			if err != nil {
				return nil, err
			}
		}
	} else if n.Upgrade != nil {
		return nil, invalid
	}
	return a, nil
}
