package reference

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

func TestPasskeyTOTPSelectionNeverFallsBackAndRetainedHandleDeniesShutdown(t *testing.T) {
	var zero FeatureSet
	if owner, err := zero.PasskeyTOTP(); err == nil || owner != nil {
		t.Fatal("zero graph exposed passkey TOTP")
	}
	_, _, graph := serverFixture(t)
	graph.state.features.magicTOTP = &magicLinkTOTPService{}
	graph.state.features.passwordTOTP = &magicLinkTOTPService{}
	graph.state.features.passkey = &passkeyState{}
	if owner, err := graph.PasskeyTOTP(); err == nil || owner != nil {
		t.Fatal("other login or known-empty passkey selection enabled passkey TOTP")
	}
	graph.state.features.passkey.totp = &magicLinkTOTPService{}
	owner, err := graph.PasskeyTOTP()
	if err != nil || owner == nil {
		t.Fatal("selected passkey TOTP handle unavailable", err)
	}
	if result, err := owner.TotpVerify(t.Context(), nativeTOTPRequest(t)); err == nil || result.Session.Token != (session.Token{}) {
		t.Fatal("uninitialized graph authenticated passkey TOTP")
	}
	graph.state.mu.Lock()
	graph.state.closed = true
	graph.state.mu.Unlock()
	if next, err := graph.PasskeyTOTP(); err == nil || next != nil {
		t.Fatal("closed graph exposed passkey TOTP")
	}
	if result, err := owner.TotpVerify(t.Context(), nativeTOTPRequest(t)); err == nil || result.Session.Token != (session.Token{}) {
		t.Fatal("retained passkey TOTP handle bypassed shutdown")
	}
	source := owner.(interface {
		TotpVerificationRateSource(context.Context, mfa.TotpVerifyRequest) (identity.UserID, string, time.Duration, error)
	})
	if user, challenge, lifetime, err := source.TotpVerificationRateSource(t.Context(), nativeTOTPRequest(t)); err == nil || user != "" || challenge != "" || lifetime != 0 {
		t.Fatal("retained passkey TOTP rate source bypassed shutdown")
	}
}

func TestPasskeyTOTPConfigurationRetainsOpaqueCustody(t *testing.T) {
	c := PasskeyTOTPConfiguration{}
	if _, err := json.Marshal(c); err == nil {
		t.Fatal("passkey TOTP startup configuration serialized")
	}
	if fmt.Sprintf("%#v", c) != "reference.PasskeyTOTPConfiguration(redacted)" {
		t.Fatal("passkey TOTP startup configuration exposed")
	}
}
