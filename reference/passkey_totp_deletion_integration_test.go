//go:build integration

package reference_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

// A second genuine signin must wait for a new acceptable TOTP step. Do this
// before creating its primary proof, rather than advancing factor state or
// letting the original twenty-second positive evidence expire during a wait.
func referenceRemovalTOTPCompletion(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, c reference.StoreConfiguration, user identity.UserID, factor mfa.FactorID, secret []byte, discoverable bool) removalSessionCompletion {
	t.Helper()
	waitReferenceRemovalTOTPStep(t, ctx, f, user, factor)
	return removalSessionCompletion{discoverable: discoverable, finish: func(primary passkey.SigninResult, browser passkey.DiscoverableSigninRequest, cookie string) removalSessionResult {
		t.Helper()
		if primary.Challenge == nil || primary.Challenge.Method != "totp" || primary.Session.Token != (session.Token{}) || primary.CSRF != (session.CSRFToken{}) {
			t.Fatal("surviving key bypassed the independent TOTP factor")
		}
		defer func() {
			_ = primary.Challenge.Proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
		}()
		completion, err := features.PasskeyTOTP()
		if err != nil {
			t.Fatal(err)
		}
		command, _ := identity.NewCommandID()
		code, _ := auth.NewOneTimeCode(passwordMFAFixtureCode(secret, time.Now().Add(30*time.Second)))
		request := mfa.TotpVerifyRequest{TenantID: otpTenant, CommandID: command, ChallengeID: mfa.ChallengeID(primary.Challenge.ID), FactorID: factor, Proof: primary.Challenge.Proof, Code: code, PreAuthID: browser.FlowID, Cookie: auth.NewBearerCredential(cookie), Origin: browser.Origin, Callback: c.Passkey.Flow.CallbackURL, Network: browser.Network, Device: browser.Device, Caller: authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.mfa.totp-verify", Resource: authorization.Resource{Type: "identity.mfa-continuation", ID: authorization.ResourceID(primary.Challenge.ID)}}}}
		out, err := completion.TotpVerify(ctx, request)
		if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.Session.Token == (session.Token{}) || out.CSRFToken == (session.CSRFToken{}) {
			t.Fatal("surviving key could not complete genuine TOTP", err)
		}
		return removalSessionResult{Session: out.Session, CSRF: out.CSRFToken}
	}}
}

func waitReferenceRemovalTOTPStep(t *testing.T, ctx context.Context, f liveStores, user identity.UserID, factor mfa.FactorID) {
	t.Helper()
	var last int64
	if err := f.pool.Raw().QueryRow(ctx, `SELECT last_step::bigint FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=2`, otpTenant, string(user), string(factor)).Scan(&last); err != nil {
		t.Fatal("original TOTP replay state absent", err)
	}
	if delay := time.Until(time.Unix(last*30, 0).Add(time.Millisecond)); delay > 0 {
		if delay > 31*time.Second {
			t.Fatal("original TOTP replay step exceeds selected skew")
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}
