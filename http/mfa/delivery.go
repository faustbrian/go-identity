package mfahttp

import (
	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

func deliver(c TOTPVerifyConfig, s input, result mfa.TotpVerifyResult) (string, string, string, func() bool, error) {
	return deliverCompletion(c, s, completionResult{Outcome: result.Outcome, Session: result.Session, CSRFToken: result.CSRFToken})
}

func deliverCompletion(c TOTPVerifyConfig, s input, result completionResult) (string, string, string, func() bool, error) {
	deny := func() (string, string, string, func() bool, error) {
		return "", "", "", nil, identityhttp.ErrUnavailable
	}
	spec, err := result.Session.Session.Bindings()
	factor, fe := result.Session.Session.MFAAuthentication().Bindings()
	primary, pe := result.Session.Session.MagicLinkAuthentication().Bindings()
	csrfState, ce := result.Session.Session.CSRFState().Bindings()
	now := c.Now()
	primaryID, primaryAt, primaryUntil := primary.CommandID, primary.AuthenticatedAt, primary.ValidUntil
	primaryValid := pe == nil && spec.Authentication.Kind == session.AuthenticationMagicLink
	tenant, command, continuation, factorID := s.request.TenantID, s.request.CommandID, string(s.request.ChallengeID), string(s.request.FactorID)
	method := "totp"
	factorValid := factor.FactorID == factorID
	if s.recovery.CommandID != "" {
		tenant, command, continuation = s.recovery.TenantID, s.recovery.CommandID, string(s.recovery.ContinuationID)
		method = "recovery-code"
		factorValid = factor.FactorID != "" && factor.RecoverySetID != "" && factor.RecoverySetVersion != 0
	} else if s.otp.CommandID != "" {
		tenant, command, continuation = s.otp.TenantID, s.otp.CommandID, string(s.otp.ContinuationID)
		method = "otp"
		// The native original send, not login JSON, selects this factor.
		factorValid = factor.FactorID != "" && factor.RecoverySetID == "" && factor.RecoverySetVersion == 0
	}
	if c.PasswordPrimary {
		proof := spec.Authentication.Proof
		primaryID, primaryAt, primaryUntil = identity.CommandID(proof.ID), proof.IssuedAt, proof.ExpiresAt
		primaryValid = spec.Authentication.Kind == session.AuthenticationVerified && proof.Method == "password" && proof.Assurance == auth.AssuranceSingleFactor && proof.Validate(auth.ProofUse{Tenant: string(spec.TenantID), Subject: string(spec.UserID), Purpose: session.PasswordMFAPrimaryPurpose, Audience: c.Audience, Now: now}) == nil
	}
	if err != nil || fe != nil || !primaryValid || ce != nil || spec.TenantID != tenant || spec.UserID != s.rate.UserID || spec.Audience != c.Audience || factor.Method != method || factor.CommandID != command || string(factor.ContinuationID) != s.rate.ChallengeID || string(factor.ContinuationID) != continuation || !factorValid || factor.PrimaryCommandID != primaryID || result.Session.Cookie.Value != "" || csrfState.Binding != (session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}) {
		return deny()
	}
	fresh := func() (valid bool) {
		defer func() {
			if recover() != nil {
				valid = false
			}
		}()
		at := c.Now()
		if now.IsZero() || at.Before(now) || at.Before(spec.IssuedAt) || at.Before(factor.VerifiedAt) || at.Before(primaryAt) || !at.Before(factor.ValidUntil) || !at.Before(primaryUntil) {
			return false
		}
		_, err := spec.Remember.Evaluate(at, spec.IssuedAt, spec.LastActivityAt, primaryAt)
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
