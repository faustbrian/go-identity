package mfa

import (
	"fmt"
	"log/slog"
	"net"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/session"
)

// OTPEnrollmentSelection selects an existing verified identifier, not an
// arbitrary recipient or a claim that OTP enrollment has completed. The native
// owner must enforce current identifier ownership/verification, exact channel,
// explicit method policy, recent primary authentication and actual confirmation.
// No canonical destination, code or provider credential is caller-selectable.
// Borrowed selection must remain unchanged throughout the bounded Enable call.
type OTPEnrollmentSelection struct {
	Channel      delivery.Channel
	IdentifierID identity.IdentifierID
}

// Validate checks intrinsic bounds only, with no IO, normalization or policy.
// Passing this method cannot prove a verified recipient or authorize enrollment.
func (s OTPEnrollmentSelection) Validate() error {
	if _, err := identity.ParseIdentifierID(string(s.IdentifierID)); err != nil ||
		(s.Channel != delivery.ChannelEmail && s.Channel != delivery.ChannelSMS) {
		return identity.InvalidInputError{Field: "mfa_otp_enrollment_selection"}
	}
	return nil
}

// Format redacts sensitive recipient-selection metadata.
func (OTPEnrollmentSelection) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.OTPEnrollmentSelection(redacted)"))
}

// MarshalJSON denies implicit recipient-selection export.
func (OTPEnrollmentSelection) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText denies implicit textual recipient-selection export.
func (OTPEnrollmentSelection) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue redacts recipient-selection metadata in structured logs.
func (OTPEnrollmentSelection) LogValue() slog.Value {
	return slog.StringValue("mfa.OTPEnrollmentSelection(redacted)")
}

// OTPEnrollmentContext explicitly borrows the original authenticated session
// and synchronizer for sending/confirming a pending OTP factor. It is disjoint
// from a partial-login child. Native composition must restore original enable
// custody and enforce current authority, origin and unchanged primary freshness.
// Structural validation creates no OTP, proof, session or enrollment authority.
type OTPEnrollmentContext struct {
	Session   auth.BearerCredential
	CSRFToken session.CSRFToken
}

func validOTPEnrollmentInput(tenant identity.TenantID, command identity.CommandID,
	factor FactorID, caller authorization.DecisionContext, origin, network string,
	custody OTPEnrollmentContext, action authorization.Action, keyed bool) bool {
	if _, err := identity.ParseIdentifierID(string(tenant)); err != nil {
		return false
	}
	if keyed {
		if command != "" {
			return false
		}
	} else {
		if _, err := identity.ParseCommandID(string(command)); err != nil {
			return false
		}
	}
	if _, err := identity.ParseCommandID(string(factor)); err != nil || command == identity.CommandID(factor) {
		return false
	}
	if _, err := session.ParseToken(custody.Session.Token()); err != nil || custody.CSRFToken == (session.CSRFToken{}) {
		return false
	}
	r := caller.Request
	if len(r.Attributes) > 64 || len(r.Subject.Groups) > 64 || len(r.Subject.Attributes) > 64 || len(r.Resource.Attributes) > 64 || len(r.Environment.Attributes) > 64 {
		return false
	}
	if caller.Validate() != nil || caller.PolicyRevision == 0 || r.Tenant != authorization.TenantID(tenant) || r.Action != action || r.Subject.Kind != authorization.SubjectUser || r.Resource.Type != "identity.user" || r.Resource.ID != authorization.ResourceID(r.Subject.ID) {
		return false
	}
	if _, err := identity.ParseIdentifierID(string(r.Subject.ID)); err != nil {
		return false
	}
	return totpCompletionURL(origin, true) && len(network) <= 255 && net.ParseIP(network) != nil
}

// Format redacts original session and synchronizer custody.
func (OTPEnrollmentContext) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.OTPEnrollmentContext(redacted)"))
}

// MarshalJSON denies implicit credential export.
func (OTPEnrollmentContext) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText denies implicit textual credential export.
func (OTPEnrollmentContext) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue redacts enrollment custody in structured logs.
func (OTPEnrollmentContext) LogValue() slog.Value {
	return slog.StringValue("mfa.OTPEnrollmentContext(redacted)")
}
