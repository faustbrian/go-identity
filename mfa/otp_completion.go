package mfa

import (
	"context"
	"fmt"
	"log/slog"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/session"
)

// OtpSendRequest selects an enrolled secondary OTP factor under the original
// partial-authentication continuation. It is not ordinary OTP signin. The native
// owner must authenticate Proof and actual original Cookie, require explicit
// current OTP policy and confirmed enrollment, and resolve the verified
// recipient itself. No destination, subject, expiry, remember choice or policy
// override is accepted. Sending does not consume the child or issue a session.
// IdempotencyKey binds original intent; it cannot authorize another send.
// The native request-key owner assigns CommandID; no request-selected command
// identity competes with that key or is silently ignored.
// Caller and transport fields are trusted composition inputs, not client JSON.
// Borrowed secrets and Caller maps must remain unchanged until the call returns.
type OtpSendRequest struct {
	TenantID                          identity.TenantID
	ContinuationID                    ContinuationID
	FactorID                          FactorID
	Channel                           delivery.Channel
	IdempotencyKey                    identity.IdempotencyKey
	Proof                             capability.Proof
	PreAuthID                         identity.PreAuthTransactionID
	Cookie                            auth.BearerCredential
	Caller                            authorization.DecisionContext
	Origin, Callback, Network, Device string
	// Enrollment explicitly selects sending for a pending authenticated
	// enrollment instead of a login child. All login-child fields must be absent.
	// The native owner restores original enable provenance, not a new primary.
	Enrollment *OTPEnrollmentContext
}

// Validate checks bounded structure only, without IO, authentication, policy,
// code generation or consumption. A supported channel is a policy request,
// not evidence of enrollment, ownership or delivery availability.
func (r OtpSendRequest) Validate() error {
	bad := identity.InvalidInputError{Field: "mfa_otp_send"}
	if r.Enrollment != nil {
		if r.ContinuationID != "" || r.PreAuthID != "" || r.Proof != (capability.Proof{}) ||
			r.Cookie.Token() != "" || r.Callback != "" || r.Device != "" ||
			!validOTPEnrollmentInput(r.TenantID, "", r.FactorID, r.Caller,
				r.Origin, r.Network, *r.Enrollment, "identity.mfa.otp-send", true) {
			return bad
		}
	} else if !validOTPBrowserInput(continuationBrowserInput{tenant: r.TenantID,
		keyed: true, continuation: r.ContinuationID, flow: r.PreAuthID,
		proof: r.Proof, cookie: r.Cookie, caller: r.Caller, origin: r.Origin,
		callback: r.Callback, network: r.Network, device: r.Device}, "identity.mfa.otp-send") {
		return bad
	}
	if _, err := identity.ParseCommandID(string(r.FactorID)); err != nil ||
		(r.Channel != delivery.ChannelEmail && r.Channel != delivery.ChannelSMS) ||
		r.IdempotencyKey == (identity.IdempotencyKey{}) {
		return bad
	}
	return nil
}

// OtpSendResult separates historical durable outcome and queue status from
// factor authentication. Accepted or queued never means delivered or verified.
// ChallengeID identifies only this purpose-bound issuance, not possession or
// permission to reset the continuation's original shared budget or deadline.
// Unknown/recovered output cannot redeliver a code or invent another challenge.
type OtpSendResult struct {
	CommandID     identity.CommandID
	Outcome       identity.CommitOutcome
	DeliveryState delivery.DeliveryState
	ChallengeID   string
}

// OtpVerifyRequest borrows the original child/browser custody and submitted
// purpose-bound code. The native owner restores the exact enrolled-factor and
// OTP issuance from original durable send provenance; a caller cannot select
// another recipient, challenge generation, primary proof or remember policy.
// The OTP contributor and MFA continuation/capability/session participants must
// reserve, apply and finalize in the same coordinator work. A non-consuming
// precheck is never authority. TrustDevice=false issues none; true requires
// explicit supported policy and must otherwise deny, not silently downgrade.
type OtpVerifyRequest struct {
	TenantID                          identity.TenantID
	CommandID                         identity.CommandID
	ContinuationID                    ContinuationID
	Code                              auth.OneTimeCode
	TrustDevice                       bool
	Proof                             capability.Proof
	PreAuthID                         identity.PreAuthTransactionID
	Cookie                            auth.BearerCredential
	Caller                            authorization.DecisionContext
	Origin, Callback, Network, Device string
	// FactorID and Enrollment are present together only for explicit pending
	// enrollment confirmation. Login restores the original send's selected
	// factor; it cannot use this field to select a different factor or recipient.
	FactorID   FactorID
	Enrollment *OTPEnrollmentContext
}

// Validate checks bounded original structure, not factor or flow authority.
// Well-formed wrong codes reach the native shared-attempt policy. No digest
// produced by this structural check is retained or used to authenticate a code.
func (r OtpVerifyRequest) Validate() error {
	bad := identity.InvalidInputError{Field: "mfa_otp_verify"}
	if r.Enrollment != nil {
		if r.ContinuationID != "" || r.PreAuthID != "" || r.Proof != (capability.Proof{}) ||
			r.Cookie.Token() != "" || r.Callback != "" || r.Device != "" ||
			!validOTPEnrollmentInput(r.TenantID, r.CommandID, r.FactorID, r.Caller,
				r.Origin, r.Network, *r.Enrollment, "identity.mfa.otp-verify", false) {
			return bad
		}
	} else if r.FactorID != "" || !validOTPBrowserInput(continuationBrowserInput{tenant: r.TenantID,
		command: r.CommandID, continuation: r.ContinuationID, flow: r.PreAuthID,
		proof: r.Proof, cookie: r.Cookie, caller: r.Caller, origin: r.Origin,
		callback: r.Callback, network: r.Network, device: r.Device}, "identity.mfa.otp-verify") {
		return bad
	}
	digest, err := r.Code.CommandDigest([32]byte{1}, "mfa.otp.input.validation")
	clear(digest[:])
	if err != nil {
		return bad
	}
	return nil
}

func validOTPBrowserInput(i continuationBrowserInput, action authorization.Action) bool {
	r := i.caller.Request
	if len(r.Attributes) > 64 || len(r.Subject.Groups) > 64 ||
		len(r.Subject.Attributes) > 64 || len(r.Resource.Attributes) > 64 ||
		len(r.Environment.Attributes) > 64 {
		return false
	}
	return validContinuationBrowserInput(i, action) && i.caller.Validate() == nil
}

// OtpVerifyResult separates committed MFA completion from ephemeral credential
// delivery. Only a fresh error-free reconciled commit may carry Session/CSRFToken
// or a selected step-up proof. Unknown, replay, recovery, cancellation and failed
// delivery carry no credential. Session metadata is historical, not current
// authority. Unsupported session/step-up variants must deny at construction or
// execution rather than treating one as the other.
type OtpVerifyResult struct {
	Outcome     identity.CommitOutcome
	Session     session.IssueResult
	StepUpProof ContinuationProof
	CSRFToken   session.CSRFToken
	// Enrollment is historical confirmation metadata only for the explicit
	// enrollment variant. That variant creates no login session or step-up proof.
	Enrollment Enrollment
}

// OTPCompletionService is the secondary-factor OTP portion of the MFA service.
// Native composition supplies actual enrollment/policy/primary/OTP/delivery/
// session owners. Applications supply bounded policy/configuration, not missing
// domain workflows. Recovery is original-command code/proof-free reconciliation,
// never another comparison, send, attempt debit, session issue or secret reveal.
// Implementations must honor cancellation and be safe for concurrent calls.
type OTPCompletionService interface {
	OtpSend(context.Context, OtpSendRequest) (OtpSendResult, error)
	RecoverOtpSend(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (OtpSendResult, error)
	OtpVerify(context.Context, OtpVerifyRequest) (OtpVerifyResult, error)
	RecoverOtpVerify(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (OtpVerifyResult, error)
}

// Format redacts code-free but sensitive primary/factor/browser send custody.
func (OtpSendRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.OtpSendRequest(redacted)"))
}

// MarshalJSON denies implicit primary/factor/browser export.
func (OtpSendRequest) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText denies implicit textual request export.
func (OtpSendRequest) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue redacts the send request in structured logs.
func (OtpSendRequest) LogValue() slog.Value { return slog.StringValue("mfa.OtpSendRequest(redacted)") }

// Format redacts historical issuance and delivery correlation.
func (OtpSendResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.OtpSendResult(redacted)"))
}

// MarshalJSON denies implicit historical result export.
func (OtpSendResult) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText denies implicit textual result export.
func (OtpSendResult) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue redacts correlated delivery result metadata.
func (OtpSendResult) LogValue() slog.Value { return slog.StringValue("mfa.OtpSendResult(redacted)") }

// Format redacts the submitted OTP and original primary/browser custody.
func (OtpVerifyRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.OtpVerifyRequest(redacted)"))
}

// MarshalJSON denies implicit code/proof/browser export.
func (OtpVerifyRequest) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText denies implicit textual request export.
func (OtpVerifyRequest) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue redacts verification custody in structured logs.
func (OtpVerifyRequest) LogValue() slog.Value {
	return slog.StringValue("mfa.OtpVerifyRequest(redacted)")
}

// Format redacts ephemeral session/step-up credential delivery.
func (OtpVerifyResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.OtpVerifyResult(redacted)"))
}

// MarshalJSON denies implicit reveal-once credential export.
func (OtpVerifyResult) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText denies implicit textual credential export.
func (OtpVerifyResult) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue redacts credential delivery and correlated metadata.
func (OtpVerifyResult) LogValue() slog.Value {
	return slog.StringValue("mfa.OtpVerifyResult(redacted)")
}
