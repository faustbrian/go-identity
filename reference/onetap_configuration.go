package reference

import (
	"fmt"
	"io"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

const oneTapReferenceField = "reference_onetap"

// OneTapConfiguration opts into native Google initiation and, when Completion
// is set, sign-in for existing linked accounts. Redirect explicitly selects
// the registered redirect-button profile instead of the default popup. Start uses the
// Reference graph's original PostgreSQL session repository, authoritative
// clock, risk evaluator and keys, capability preparation and audit retention.
// The configured provider is borrowed; keep its lifetime through StoreSet.
type OneTapConfiguration struct {
	Start      oauthpg.OneTapStartConfig
	Completion *oauthpg.OneTapCompletionConfig
	Redirect   bool
}

// HTTPOneTapConfiguration selects the native owner's exact Start and/or
// callback HTTP routes for the single profile selected by OneTapConfiguration.
// Neither enables generic OAuth, signup or linking. Callback needs the graph's
// existing synchronizer policy.
type HTTPOneTapConfiguration struct {
	EnableStart, EnableCallback bool
	CSRFCookie                  session.CSRFCookiePolicy
}

type oneTapState struct {
	start       *oauthpg.OneTapStartService
	complete    *oauthpg.OneTapCompletionService
	profile     oauth.ProviderProfile
	issuance    session.PreAuthIssuerConfig
	finalCookie session.CookiePolicy
	csrfCookie  session.CSRFCookiePolicy
	schema      string
	session     sessionpg.Config
	tenant      identity.TenantID
	audience    string
	duration    time.Duration
	redirect    bool
	http        HTTPOneTapConfiguration
}

const oneTapCallbackPath = "/v1/oauth/onetap-callback"

func validateOneTapSelection(c StoreConfiguration) error {
	invalid := identity.InvalidInputError{Field: oneTapReferenceField}
	if c.OneTap == nil {
		if c.HTTPOneTap != nil {
			return invalid
		}
		return nil
	}
	if c.OTP == nil || c.PasswordSignup == nil || c.PasswordSignin == nil || c.Session == nil ||
		c.ProviderDiscovery != nil || c.OAuthWorkload != nil || c.Passkey != nil && c.Passkey.Standalone != nil {
		return invalid
	}
	if c.HTTPOneTap != nil && c.OTP.PreAuth == nil {
		return invalid
	}
	return nil
}

func composeOneTap(c StoreConfiguration, d ReferenceDependencies, selectedSession *sessionState, evaluation risk.Evaluator) (*oneTapState, error) {
	invalid := identity.InvalidInputError{Field: oneTapReferenceField}
	if c.OneTap == nil {
		return nil, nil
	}
	if selectedSession == nil || d.PostgreSQL == nil {
		return nil, invalid
	}
	n := *c.OneTap
	start, execution := n.Start, c.Session.Native.Execution
	if !slices.Contains(c.PasswordSignin.Native.Origins, start.Issuance.Origin) || start.MaximumDuration > c.OTP.Timeout ||
		(c.SocialOAuth != nil && start.Schema == c.SocialOAuth.Schema) ||
		(start.Session != (sessionpg.Config{}) && start.Session != execution.Repository) ||
		(start.GlobalAuthorityID != "" && start.GlobalAuthorityID != execution.Profile.GlobalAuthorityID) ||
		(start.AuditRetentionPolicyVersion != 0 && start.AuditRetentionPolicyVersion != execution.AuditRetentionVersion) {
		return nil, invalid
	}
	policy := c.OTP.RequestKeys.Policy
	for _, selected := range []*kernel.CommandQueryPolicy{start.Coordinator.QueryPolicy, start.Coordinator.AdmissionPolicy} {
		if selected == nil || selected.PolicyVersion != policy.PolicyVersion || !sameServerAuthorization(selected.Authorization, policy.Authorization) {
			return nil, invalid
		}
	}
	start.Session, start.GlobalAuthorityID, start.AuditRetentionPolicyVersion = execution.Repository, execution.Profile.GlobalAuthorityID, execution.AuditRetentionVersion
	start.Issuance.Clock = execution.Clock
	start.CapabilityPreparation = c.PasswordSignup.Preparation
	start.Risk.Evaluation, start.Risk.Keys = evaluation, c.OTP.RiskKeys
	newStart, newCompletion := oauthpg.NewOneTapStartService, oauthpg.NewOneTapCompletionService
	if n.Redirect {
		newStart, newCompletion = oauthpg.NewOneTapRedirectStartService, oauthpg.NewOneTapRedirectCompletionService
	}
	service, err := newStart(d.PostgreSQL, start)
	if err != nil {
		return nil, err
	}
	state := &oneTapState{start: service, profile: start.Provider.Profile(), issuance: start.Issuance,
		schema: start.Schema, session: execution.Repository, tenant: start.TenantID, audience: execution.Profile.Audience, duration: start.MaximumDuration, redirect: n.Redirect}
	if n.Completion != nil {
		completion := *n.Completion
		if completion.PolicyNamespace != execution.Profile.PolicyNamespace || completion.Audience != execution.Profile.Audience ||
			!sessionIssuanceMatches(*c.Session, completion.Issuer, completion.CSRF) || !oneTapFlowKeyRetained(start.Issuance.LookupKey, completion.FlowKeys) {
			return nil, invalid
		}
		state.complete, err = newCompletion(service, completion)
		if err != nil {
			return nil, err
		}
		state.finalCookie = completion.Issuer.Cookie
	}
	if c.HTTPOneTap != nil {
		h := *c.HTTPOneTap
		if (!h.EnableStart && !h.EnableCallback) || c.HTTPRate == nil || c.HTTPPreAuth == nil || c.HTTPPreAuth.Device == nil ||
			start.Issuance.Origin != c.OTP.PreAuth.Origin || (h.EnableCallback && state.complete == nil) {
			return nil, invalid
		}
		if n.Redirect {
			if start.Issuance.CallbackURL != start.Issuance.Origin+oneTapCallbackPath {
				return nil, invalid
			}
		} else {
			flow, e := start.Issuance.Cookie.DeletionAttributes()
			original, o := c.OTP.PreAuth.Cookie.DeletionAttributes()
			if e != nil || o != nil || flow.String() != original.String() {
				return nil, invalid
			}
		}
		if h.EnableCallback {
			if _, err := h.CSRFCookie.DeletionAttributes(); err != nil {
				return nil, invalid
			}
		}
		state.http, state.csrfCookie = h, h.CSRFCookie
	}
	return state, nil
}

// Compare the opaque keys using their owned digest operation, not pointer
// identity. This public test vector is neither issued nor durably recorded.
func oneTapFlowKeyRetained(current session.DigestKey, retained map[uint32]session.DigestKey) bool {
	const probe = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	parsed, err := session.ParseToken(probe)
	if err != nil {
		return false
	}
	expected, err := parsed.Digest(current, "reference-onetap-flow-profile")
	if err != nil {
		return false
	}
	actual, err := parsed.Digest(retained[expected.KeyVersion], "reference-onetap-flow-profile")
	return err == nil && expected == actual
}

func (OneTapConfiguration) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "reference.OneTapConfiguration(redacted)")
}
func (OneTapConfiguration) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (OneTapConfiguration) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }
