package mfa_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/mfa"
)

func otpSendFixture(t *testing.T) mfa.OtpSendRequest {
	t.Helper()
	r := totpRequestFixture(t)
	r.Caller.Request.Action = "identity.mfa.otp-send"
	key, err := identity.NewIdempotencyKey([]byte("synthetic-mfa-otp-send"))
	if err != nil {
		t.Fatal(err)
	}
	return mfa.OtpSendRequest{TenantID: r.TenantID,
		ContinuationID: mfa.ContinuationID(r.ChallengeID), FactorID: r.FactorID,
		Channel: delivery.ChannelEmail, IdempotencyKey: key, Proof: r.Proof,
		PreAuthID: r.PreAuthID, Cookie: r.Cookie, Caller: r.Caller, Origin: r.Origin,
		Callback: r.Callback, Network: r.Network, Device: r.Device}
}

func otpVerifyFixture(t *testing.T) mfa.OtpVerifyRequest {
	t.Helper()
	r := totpRequestFixture(t)
	r.Caller.Request.Action = "identity.mfa.otp-verify"
	return mfa.OtpVerifyRequest{TenantID: r.TenantID, CommandID: r.CommandID,
		ContinuationID: mfa.ContinuationID(r.ChallengeID), Code: r.Code, Proof: r.Proof,
		PreAuthID: r.PreAuthID, Cookie: r.Cookie, Caller: r.Caller, Origin: r.Origin,
		Callback: r.Callback, Network: r.Network, Device: r.Device}
}

// These are structural public-boundary assertions, not proof of enrollment,
// possession, provider delivery, consumption or session creation.
func TestMFAOTPSendInputBounds(t *testing.T) {
	r := otpSendFixture(t)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*mfa.OtpSendRequest){
		func(r *mfa.OtpSendRequest) { r.Channel = 0 },
		func(r *mfa.OtpSendRequest) { r.Channel = 255 },
		func(r *mfa.OtpSendRequest) { r.FactorID = "" },
		func(r *mfa.OtpSendRequest) { r.FactorID = "noncanonical" },
		func(r *mfa.OtpSendRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		func(r *mfa.OtpSendRequest) { r.Proof = capability.Proof{} },
		func(r *mfa.OtpSendRequest) { r.Cookie = auth.BearerCredential{} },
		func(r *mfa.OtpSendRequest) { r.Caller.Request.Action = "identity.otp.send" },
		func(r *mfa.OtpSendRequest) { r.Origin += "#" },
	} {
		changed := r
		mutate(&changed)
		if err := changed.Validate(); err == nil || !errors.As(err, new(identity.InvalidInputError)) {
			t.Fatal("invalid secondary-factor send input admitted")
		}
	}
	r.Channel = delivery.ChannelSMS
	if err := r.Validate(); err != nil {
		t.Fatal("channel policy is native authority, not structural validation", err)
	}
}

func TestMFASendRequestKeyDoesNotRequireCallerCommandIdentity(t *testing.T) {
	r := otpSendFixture(t)
	if err := r.Validate(); err != nil {
		t.Fatal("keyed send requires a caller-selected command before native admission", err)
	}
}

func TestMFAOTPVerifyInputBounds(t *testing.T) {
	r := otpVerifyFixture(t)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*mfa.OtpVerifyRequest){
		func(r *mfa.OtpVerifyRequest) { r.TenantID = "" },
		func(r *mfa.OtpVerifyRequest) { r.CommandID = "" },
		func(r *mfa.OtpVerifyRequest) { r.CommandID = identity.CommandID(r.ContinuationID) },
		func(r *mfa.OtpVerifyRequest) { r.ContinuationID = "" },
		func(r *mfa.OtpVerifyRequest) { r.Code = auth.OneTimeCode{} },
		func(r *mfa.OtpVerifyRequest) { r.Proof = capability.Proof{} },
		func(r *mfa.OtpVerifyRequest) { r.PreAuthID = "" },
		func(r *mfa.OtpVerifyRequest) { r.Cookie = auth.BearerCredential{} },
		func(r *mfa.OtpVerifyRequest) { r.Origin += "/path" },
		func(r *mfa.OtpVerifyRequest) { r.Callback += "#" },
		func(r *mfa.OtpVerifyRequest) { r.Network = "invalid" },
		func(r *mfa.OtpVerifyRequest) { r.Device = strings.Repeat("x", 256) },
		func(r *mfa.OtpVerifyRequest) { r.Caller.Request.Tenant = "foreign" },
		func(r *mfa.OtpVerifyRequest) { r.Caller.Request.Action = "identity.otp.signin" },
		func(r *mfa.OtpVerifyRequest) { r.Caller.PolicyRevision = 0 },
		func(r *mfa.OtpVerifyRequest) { r.Caller.Request.Resource.ID = "foreign" },
	} {
		changed := r
		mutate(&changed)
		if err := changed.Validate(); err == nil || !errors.As(err, new(identity.InvalidInputError)) {
			t.Fatal("invalid secondary-factor verification input admitted")
		}
	}
	r.TrustDevice = true
	if err := r.Validate(); err != nil {
		t.Fatal("explicit trusted-device policy request is not malformed", err)
	}
}

func TestMFAOTPBoundaryCustodyRedacted(t *testing.T) {
	values := []struct {
		value any
		name  string
	}{
		{otpSendFixture(t), "mfa.OtpSendRequest(redacted)"},
		{otpVerifyFixture(t), "mfa.OtpVerifyRequest(redacted)"},
		{mfa.OtpSendResult{}, "mfa.OtpSendResult(redacted)"},
		{mfa.OtpVerifyResult{}, "mfa.OtpVerifyResult(redacted)"},
	}
	for _, v := range values {
		if got := fmt.Sprintf("%#v", v.value); got != v.name {
			t.Fatal("OTP boundary disclosed custody")
		}
		if _, err := json.Marshal(v.value); err == nil {
			t.Fatal("OTP boundary serialized implicitly")
		}
	}
}
