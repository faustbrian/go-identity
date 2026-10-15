//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

type otpSigninCapture struct{ codes chan<- auth.OneTimeCode }

func (s otpSigninCapture) Send(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
	code, err := auth.NewOneTimeCode(a.Body)
	if err != nil {
		return delivery.DeliveryResult{}, err
	}
	select {
	case s.codes <- code:
		return delivery.DeliveryResult{State: delivery.StateAccepted, ObservedAt: time.Now().UTC()}, nil
	case <-ctx.Done():
		return delivery.DeliveryResult{}, ctx.Err()
	}
}

type otpReferenceSigninPolicy struct{}

func (otpReferenceSigninPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && (c.Request.Action == "identity.otp.signin" || c.Request.Action == "identity.otp.signin.recover") {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	return (otpGraphPolicy{}).Decide(ctx, c)
}

func configureReferenceSignin(t *testing.T, c *reference.StoreConfiguration) {
	t.Helper()
	key, err := session.NewDigestKey(11, bytes.Repeat([]byte{0x79}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFKey(12, bytes.Repeat([]byte{0x7a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	if err != nil {
		t.Fatal(err)
	}
	coordinator := c.OTP.Coordinator
	coordinator.QueryPolicy = &kernel.CommandQueryPolicy{Clock: clock.System{}, Authorization: otpReferenceSigninPolicy{}, PolicyVersion: 9}
	c.OTP.Signin = &otppg.SigninConfig{Coordinator: coordinator, CurrentAttemptKeyVersion: 7,
		Session: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second},
		Profile: sessionpg.OTPAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a"},
		Issuer:  session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 3 * time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie}, CSRFKey: csrf}
}

func proveReferenceSignin(t *testing.T, ctx context.Context, stores reference.StoreSet, features reference.FeatureSet, workers reference.WorkerSet, f liveStores, send otp.SendRequest, sent otp.SendResult, codes <-chan auth.OneTimeCode) {
	t.Helper()
	reader, err := features.OTPSigninSource()
	if err != nil {
		t.Fatal("selected source reader", err)
	}
	source, err := reader.ResolveSigninSource(ctx, otp.SigninSourceRequest{TenantID: send.TenantID, UserID: send.UserID, Caller: send.Caller, Flow: send.Flow, SendCommandID: sent.CommandID})
	binding, bindingErr := source.Bindings()
	if err != nil || bindingErr != nil || binding.TenantID != send.TenantID || binding.SendCommandID != sent.CommandID || binding.Channel != send.Channel || binding.Destination.Value() != send.Destination.Value() {
		t.Fatal("composed original identifier discovery", err, bindingErr)
	}
	var attempted, failed, sessions int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts,(SELECT count(*) FROM session_store.session_issuances) FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(send.TenantID), string(sent.CommandID)).Scan(&attempted, &failed, &sessions); err != nil || attempted != 0 || failed != 0 || sessions != 0 {
		t.Fatal("composed source reader mutated login state", err)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("native explicit delivery", err)
	}
	var code auth.OneTimeCode
	select {
	case code = <-codes:
	case <-ctx.Done():
		t.Fatal("owned delivery never produced code")
	}
	service, err := features.OTPSignin()
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Signin(ctx, otp.SigninRequest{TenantID: send.TenantID, UserID: send.UserID, Caller: send.Caller, Flow: send.Flow, SendCommandID: sent.CommandID, Code: code})
	if err != nil || result.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || result.SessionID == "" {
		t.Fatal("composed native consuming signin", err)
	}
	if _, err := result.Issuance.Token.Reveal(); err != nil {
		t.Fatal("new committed credential absent", err)
	}
	if _, err := result.CSRFToken.Reveal(); err != nil {
		t.Fatal("new committed CSRF absent", err)
	}
	var finalized, consumed, issued int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM otp_store.challenges WHERE state='finalized'),(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed'),(SELECT count(*) FROM session_store.session_issuances)`).Scan(&finalized, &consumed, &issued); err != nil || finalized != 1 || consumed != 1 || issued != 1 {
		t.Fatal("composed native effects diverged", err)
	}
	history, err := service.RecoverSignin(ctx, otp.SigninRecoveryRequest{TenantID: send.TenantID, UserID: send.UserID, Caller: send.Caller, Flow: send.Flow, Recovery: result.Recovery})
	if err != nil || history.SessionID != result.SessionID || !history.Issuance.Replayed {
		t.Fatal("composed code-free recovery lost original outcome", err)
	}
	if _, err := history.Issuance.Token.Reveal(); err == nil {
		t.Fatal("composed recovery redelivered credential")
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RecoverSignin(ctx, otp.SigninRecoveryRequest{}); err == nil {
		t.Fatal("retained signin handle survived closure")
	}
	if source, err := reader.ResolveSigninSource(ctx, otp.SigninSourceRequest{}); err == nil || source != (otp.SigninSource{}) {
		t.Fatal("retained source reader survived closure")
	}
}
