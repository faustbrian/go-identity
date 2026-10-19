package otphttp_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	identity "github.com/faustbrian/go-identity"
	otphttp "github.com/faustbrian/go-identity/http/otp"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/session"
)

// Only the transport seam is replaced. Native PostgreSQL authority and actual
// session usability are proved separately by the genuine enrolled-phone flow.
type phoneSigninOwner struct {
	t        *testing.T
	config   otphttp.SigninConfig
	channel  otp.Channel
	kind     identity.IdentifierKind
	sources  int
	attempts int
	sends    int
	lastSend phone.SigninSendRequestSpec
	send     otp.SendResult
}

func (o *phoneSigninOwner) SendSignin(ctx context.Context, r phone.SigninSendRequest) (otp.SendResult, error) {
	o.sends++
	spec, err := r.Bindings()
	if _, bounded := ctx.Deadline(); !bounded || err != nil || spec.Caller.Request.Action != "identity.phone.signin" {
		o.t.Fatal("phone issuance received invalid or unbounded native custody", err)
	}
	o.lastSend = spec
	return o.send, nil
}

func (o *phoneSigninOwner) ResolveSigninSource(ctx context.Context, r otp.SigninSourceRequest) (otp.SigninSource, error) {
	o.sources++
	if _, bounded := ctx.Deadline(); !bounded || r.Validate() != nil || r.UserID != "" || r.Caller.Request.Action != "identity.phone.signin" || r.Caller.Request.Resource.ID != "identity.phone.signin" {
		o.t.Fatal("phone source received another action, user or unbounded context")
	}
	destination, _ := otp.NewDestinationInput("+12025550123")
	return otp.NewSigninSource(otp.SigninSourceBindings{TenantID: r.TenantID, SendCommandID: r.SendCommandID, Channel: o.channel, Destination: destination})
}

func (o *phoneSigninOwner) Signin(ctx context.Context, r otp.SigninRequest) (otp.SigninResult, error) {
	o.attempts++
	if _, bounded := ctx.Deadline(); !bounded || r.Validate() != nil || r.Caller.Request.Action != "identity.phone.signin" || r.UserID != "" {
		o.t.Fatal("phone consumption received another action or user")
	}
	result := issuance(o.t, o.config, r)
	spec, _ := result.Issuance.Session.Bindings()
	metadata, _ := result.Issuance.Session.OTPAuthentication().Bindings()
	metadata.IdentifierKind = o.kind
	proof, err := session.NewOTPAuthentication(metadata)
	if err != nil {
		o.t.Fatal(err)
	}
	result.Issuance.Session, err = session.NewSessionWithOTPAndCSRF(spec, proof, result.Issuance.Session.CSRFState())
	if err != nil {
		o.t.Fatal(err)
	}
	return result, nil
}

func (*phoneSigninOwner) RecoverSignin(context.Context, otp.SigninRecoveryRequest) (otp.SigninResult, error) {
	panic("consuming transport must not retry or recover")
}

func TestPhoneSigninTransportUsesClosedOriginalSMSProfile(t *testing.T) {
	for _, mode := range []string{"phone", "email-source", "email-session", "generic-path"} {
		t.Run(mode, func(t *testing.T) {
			c, _, body := fixture(t)
			owner := &phoneSigninOwner{t: t, config: c, channel: otp.ChannelSMS, kind: identity.IdentifierPhone}
			if mode == "email-source" {
				owner.channel = otp.ChannelEmail
			}
			if mode == "email-session" {
				owner.kind = identity.IdentifierEmail
			}
			c.Service, c.Source = owner, owner
			h, err := otphttp.NewPhoneSigninHandler(c)
			if err != nil || owner.sources != 0 || owner.attempts != 0 {
				t.Fatal("phone construction invoked an owner", err)
			}
			r := request(body)
			if mode != "generic-path" {
				r.URL.Path = "/v1/phone/signin"
				r.RequestURI = r.URL.RequestURI()
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if mode == "phone" {
				if w.Code != 200 || owner.sources != 1 || owner.attempts != 1 || len(w.Result().Cookies()) != 1 || w.Header().Get("X-CSRF-Token") == "" {
					t.Fatal("phone commit did not use the original SMS flow and deliver its session", w.Code)
				}
			} else {
				if w.Code < 400 || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" {
					t.Fatal("foreign phone profile or route delivered credentials", w.Code)
				}
				if mode == "email-source" && owner.attempts != 0 || mode == "generic-path" && (owner.sources != 0 || owner.attempts != 0) {
					t.Fatal("invalid source or generic route reached consumption")
				}
			}
		})
	}
}

type phoneHistoryOwner struct {
	t      *testing.T
	result otp.SigninResult
	calls  int
}

func (o *phoneHistoryOwner) RecoverSignin(ctx context.Context, r otp.SigninRecoveryRequest) (otp.SigninResult, error) {
	o.calls++
	if _, bounded := ctx.Deadline(); !bounded || r.Validate() != nil || r.UserID != "" || r.Caller.Request.Action != "identity.phone.signin.recover" {
		o.t.Fatal("phone history received consuming or unbounded request")
	}
	return o.result, nil
}

func TestPhoneSigninRecoveryUsesDistinctActionWithoutCredentials(t *testing.T) {
	c, _, body, original := recoveryFixture(t)
	owner := &phoneHistoryOwner{t: t, result: original}
	c.Service = owner
	h, err := otphttp.NewPhoneSigninRecoveryHandler(c)
	if err != nil || owner.calls != 0 {
		t.Fatal("phone recovery construction called its owner", err)
	}
	for _, phone := range []bool{true, false} {
		r := recoveryRequest(body)
		if phone {
			r.URL.Path = "/v1/phone/signin/recover"
			r.RequestURI = r.URL.RequestURI()
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" {
			t.Fatal("phone historical recovery delivered credentials")
		}
		if phone {
			var history otphttp.SigninResponse
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &history) != nil || history.SignedIn || history.SessionID != original.SessionID || history.CommitOutcome != "committed" {
				t.Fatal("phone original history changed or claimed authentication", w.Code)
			}
		} else if w.Code != 404 {
			t.Fatal("phone recovery admitted a generic OTP route", w.Code)
		}
	}
	if owner.calls != 1 {
		t.Fatal("phone recovery retried or accepted the generic route")
	}
}
