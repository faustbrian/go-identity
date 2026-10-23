package mfapostgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

// OTPActivePrimary retains actual current-session custody for active OTP
// sending or verification. Its method-neutral participant vocabulary is the
// same as other MFA actions; it neither verifies OTP nor supplies factor proof.
// Snapshot contains no bearer and may only be restored after authenticating the
// native MFA envelope. Original deadlines cannot be renewed by restoration.
type OTPActivePrimary interface {
	TOTPURIPrimary
	Snapshot() ([]byte, error)
}

// OTPActivePrimarySource prepares the real current session for the explicit
// authenticated StepUp request arm. Send uses the request-key owner's assigned
// command; verify uses the submitted command and exact original SendCommandID.
// Neither method translates the request into enrollment or TOTP authority.
// Restores are IO-free custody checks over native-envelope-authenticated bytes;
// actual current owners, synchronizer and original deadline remain mandatory
// in the sole protected Work. Owners and request inputs are borrowed.
type OTPActivePrimarySource interface {
	PrepareOTPSend(context.Context, mfa.OtpSendRequest, identity.CommandID) (OTPActivePrimary, session.GetResult, error)
	RestoreOTPSend(context.Context, mfa.OtpSendRequest, identity.CommandID, []byte) (OTPActivePrimary, error)
	PrepareOTPVerify(context.Context, mfa.OtpVerifyRequest) (OTPActivePrimary, session.GetResult, error)
	RestoreOTPVerify(context.Context, mfa.OtpVerifyRequest, []byte) (OTPActivePrimary, error)
}
