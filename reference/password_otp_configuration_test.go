package reference

import (
	"bytes"
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	mfahttp "github.com/faustbrian/go-identity/http/mfa"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

func TestPasswordOTPGraphSelectionAndLifetime(t *testing.T) {
	var empty FeatureSet
	if owner, err := empty.PasswordOTP(); err == nil || owner != nil {
		t.Fatal("zero graph exposed secondary OTP")
	}
	_, _, graph := serverFixture(t)
	graph.state.features.passwordTOTP = &magicLinkTOTPService{}
	if owner, err := graph.PasswordOTP(); err == nil || owner != nil {
		t.Fatal("TOTP selection enabled an OTP completion fallback")
	}
	graph.state.features.passwordOTP = &PasswordOTPLoginCompletionService{}
	owner, err := graph.PasswordOTP()
	if err != nil || owner == nil {
		t.Fatal("selected graph withheld secondary OTP", err)
	}
	rateOwner, ok := owner.(mfahttp.OTPVerifyService)
	if !ok {
		t.Fatal("selected OTP handle has no native quota-source boundary")
	}
	assertDenied := func(tenant identity.TenantID) {
		t.Helper()
		if out, err := owner.OtpSend(t.Context(), mfa.OtpSendRequest{TenantID: tenant}); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("inactive/foreign OTP send bypassed graph admission")
		}
		if out, err := owner.OtpVerify(t.Context(), mfa.OtpVerifyRequest{TenantID: tenant}); err == nil || out.Session.Token != (session.Token{}) || out.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("inactive/foreign OTP verification exposed credentials")
		}
		query := identity.RecoveryQuery{TenantID: tenant}
		if _, err := owner.RecoverOtpSend(t.Context(), query, nativeTOTPRequest(t).Caller); err == nil {
			t.Fatal("inactive/foreign graph disclosed send history")
		}
		if _, err := owner.RecoverOtpVerify(t.Context(), query, nativeTOTPRequest(t).Caller); err == nil {
			t.Fatal("inactive/foreign graph disclosed verification history")
		}
		if graph.state.active != 0 {
			t.Fatal("denied OTP operation leaked graph admission")
		}
		if user, child, lifetime, err := rateOwner.OtpVerificationRateSource(t.Context(), mfa.OtpVerifyRequest{TenantID: tenant}); err == nil || user != "" || child != "" || lifetime != 0 {
			t.Fatal("inactive/foreign OTP handle exported quota identity")
		}
	}
	assertDenied("tenant")
	graph.state.features.ready = true
	assertDenied("foreign")
	graph.state.closed = true
	assertDenied("tenant")
	if next, err := graph.PasswordOTP(); err == nil || next != nil {
		t.Fatal("closed graph exported a new OTP handle")
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	stop()
	if _, err := owner.OtpSend(ctx, mfa.OtpSendRequest{TenantID: "tenant"}); err == nil {
		t.Fatal("canceled retained handle admitted OTP sending")
	}
}

func TestPasswordOTPFlowKeysMatchBothNativeOwners(t *testing.T) {
	material := bytes.Repeat([]byte{71}, 32)
	key, _ := session.NewDigestKey(1, material)
	probe, _ := session.ParseToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	got, err := passwordOTPFlowKeys([]session.DigestKey{key}, map[uint32][]byte{1: material})
	if err != nil || len(got) != 1 {
		t.Fatal("matching password and OTP browser keys rejected", err)
	}
	want, _ := probe.Digest(key, "otp-configuration")
	observed, err := probe.Digest(got[1], "otp-configuration")
	if err != nil || want != observed {
		t.Fatal("graph substituted the original password browser key")
	}
	for _, raw := range []map[uint32][]byte{nil, {2: material}, {1: bytes.Repeat([]byte{72}, 32)}, {1: material, 2: material}} {
		if keys, err := passwordOTPFlowKeys([]session.DigestKey{key}, raw); err == nil || len(keys) != 0 {
			t.Fatal("mismatched native browser key configuration admitted")
		}
	}
	if keys, err := passwordOTPFlowKeys([]session.DigestKey{key, key}, map[uint32][]byte{1: material}); err == nil || len(keys) != 0 {
		t.Fatal("duplicate browser versions admitted")
	}
}
