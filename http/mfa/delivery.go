package mfahttp

import (
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

func deliver(c TOTPVerifyConfig, s input, result mfa.TotpVerifyResult) (string, string, string, func() bool, error) {
	deny := func() (string, string, string, func() bool, error) {
		return "", "", "", nil, identityhttp.ErrUnavailable
	}
	spec, err := result.Session.Session.Bindings()
	factor, fe := result.Session.Session.MFAAuthentication().Bindings()
	primary, pe := result.Session.Session.MagicLinkAuthentication().Bindings()
	csrfState, ce := result.Session.Session.CSRFState().Bindings()
	now := c.Now()
	if err != nil || fe != nil || pe != nil || ce != nil || spec.TenantID != s.request.TenantID || spec.UserID != s.rate.UserID || spec.Audience != c.Audience || spec.Authentication.Kind != session.AuthenticationMagicLink || factor.Method != "totp" || factor.CommandID != s.request.CommandID || string(factor.ContinuationID) != s.rate.ChallengeID || string(factor.ContinuationID) != string(s.request.ChallengeID) || factor.FactorID != string(s.request.FactorID) || factor.PrimaryCommandID != primary.CommandID || result.Session.Cookie.Value != "" || csrfState.Binding != (session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}) {
		return deny()
	}
	fresh := func() (valid bool) {
		defer func() {
			if recover() != nil {
				valid = false
			}
		}()
		at := c.Now()
		if now.IsZero() || at.Before(now) || at.Before(spec.IssuedAt) || at.Before(factor.VerifiedAt) || at.Before(primary.AuthenticatedAt) || !at.Before(factor.ValidUntil) || !at.Before(primary.ValidUntil) {
			return false
		}
		_, err := spec.Remember.Evaluate(at, spec.IssuedAt, spec.LastActivityAt, primary.AuthenticatedAt)
		return err == nil
	}
	if !fresh() {
		return deny()
	}
	attributes, err := c.SessionCookie.Attributes(spec.Remember, now, spec.IssuedAt.Add(spec.Remember.AbsoluteTTL()))
	issued := result.Session.Cookie
	if err != nil || issued.Name != attributes.Name || issued.Path != attributes.Path || issued.Domain != "" || !issued.Secure || !issued.HttpOnly || issued.SameSite != attributes.SameSite || issued.Partitioned || len(issued.Unparsed) != 0 || issued.Raw != "" || issued.RawExpires != "" || (attributes.MaxAge == 0 && (issued.MaxAge != 0 || !issued.Expires.IsZero())) || (attributes.MaxAge > 0 && (issued.MaxAge <= 0 || issued.Expires.IsZero() || issued.Expires.After(spec.IssuedAt.Add(spec.Remember.AbsoluteTTL())))) {
		return deny()
	}
	csrf, err := result.CSRFToken.Reveal()
	if err != nil {
		return deny()
	}
	if _, err = session.ParseCSRFToken(csrf); err != nil {
		return deny()
	}
	token, err := result.Session.Token.Reveal()
	if err != nil {
		return deny()
	}
	if _, err = session.ParseToken(token); err != nil {
		return deny()
	}
	attributes.Value = token
	return attributes.String(), csrf, spec.SessionID, fresh, nil
}
