package mfa

import (
	"fmt"
	"log/slog"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// OTPAuthenticatedStepUp borrows a genuine current session and synchronizer
// for the explicit active-OTP factor-management profile. Purpose must be
// identity.mfa.factor-update or identity.mfa.disable; the native owner must
// explicitly select the requested purpose. SendCommandID is absent on a keyed send and names
// its original committed issuance on verification; it cannot equal the verify
// command or factor ID. No field grants authentication or permission.
//
// The native owner must resolve the factor's actual verified recipient, bind
// this exact action/session/factor/send, enforce bounded attempts and original
// freshness after waits, then consume OTP and persist signed factor evidence
// atomically. Copies cannot renew evidence. Unsupported profiles must deny;
// this is neither pending enrollment, login nor trusted-device issuance.
type OTPAuthenticatedStepUp struct {
	Session       auth.BearerCredential
	CSRFToken     session.CSRFToken
	Purpose       auth.Purpose
	SendCommandID identity.CommandID
}

func validOTPStepUpInput(tenant identity.TenantID, command identity.CommandID,
	factor FactorID, caller authorization.DecisionContext, origin, network string,
	custody OTPAuthenticatedStepUp, action authorization.Action, keyed bool) bool {
	if custody.Purpose != "identity.mfa.factor-update" && custody.Purpose != "identity.mfa.disable" {
		return false
	}
	if keyed {
		if custody.SendCommandID != "" {
			return false
		}
	} else if _, err := identity.ParseCommandID(string(custody.SendCommandID)); err != nil || custody.SendCommandID == command || custody.SendCommandID == identity.CommandID(factor) {
		return false
	}
	// Both profiles share only intrinsic authenticated request bounds. This
	// pure check neither constructs enrollment authority nor changes purpose.
	return validOTPEnrollmentInput(tenant, command, factor, caller, origin, network,
		OTPEnrollmentContext{Session: custody.Session, CSRFToken: custody.CSRFToken}, action, keyed)
}

// Format prevents traversal of borrowed browser custody.
func (OTPAuthenticatedStepUp) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.OTPAuthenticatedStepUp(redacted)"))
}

// MarshalJSON rejects implicit credential export.
func (OTPAuthenticatedStepUp) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText rejects implicit credential and map-key export.
func (OTPAuthenticatedStepUp) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue exposes only a fixed redaction marker.
func (OTPAuthenticatedStepUp) LogValue() slog.Value {
	return slog.StringValue("mfa.OTPAuthenticatedStepUp(redacted)")
}
