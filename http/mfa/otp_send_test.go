package mfahttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	rate "github.com/faustbrian/go-rate-limit/v2"
)

type otpSendRate struct {
	rate.StrictBackend
	calls int
	fail  int
}

func (*otpSendRate) Name() string { return "otp-send-test" }
func (s *otpSendRate) AdmitStrict(_ context.Context, r rate.Request) (rate.Decision, error) {
	s.calls++
	if s.calls == s.fail {
		return rate.Decision{}, rate.ErrUnavailable
	}
	return rate.Decision{Allowed: true, Limit: r.Policy.Limit(), Remaining: r.Policy.Limit() - 1, Reset: r.Now.Add(r.Policy.Period()), Reason: rate.ReasonAllowed}, nil
}

type otpSendNative struct {
	rate         *otpSendRate
	reads, calls int
	fail         bool
	result       mfa.OtpSendResult
	last         mfa.OtpSendRequest
}

func (s *otpSendNative) OtpSendingRateSource(ctx context.Context, r mfa.OtpSendRequest) (string, error) {
	s.reads++
	if _, ok := ctx.Deadline(); !ok || s.rate.calls != 1 || r.Validate() != nil || r.Enrollment != nil {
		panic("unadmitted send source")
	}
	if s.fail {
		return "", identity.ForbiddenError{}
	}
	return "native-recipient@example.test", nil
}
func (s *otpSendNative) OtpSend(ctx context.Context, r mfa.OtpSendRequest) (mfa.OtpSendResult, error) {
	s.calls++
	s.last = r
	if _, ok := ctx.Deadline(); !ok || s.rate.calls != 2 || r.Validate() != nil {
		panic("unadmitted native send")
	}
	return s.result, nil
}

func otpSendFixture(t *testing.T) (OTPSendConfig, *otpSendNative, string, *http.Cookie) {
	t.Helper()
	base, _, body, device := handlerFixture(t)
	var input map[string]any
	if err := json.Unmarshal([]byte(body), &input); err != nil {
		t.Fatal(err)
	}
	input["continuationID"] = input["challengeID"]
	delete(input, "challengeID")
	delete(input, "commandID")
	delete(input, "code")
	delete(input, "trustDevice")
	input["channel"] = "email"
	wire, _ := json.Marshal(input)
	backend := &otpSendRate{}
	limiter, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: backend, Namespace: "otp-send-test", IdentifierKey: [32]byte{2}, Now: base.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := limiter.Close(); err != nil {
			t.Error(err)
		}
	})
	id := identity.CommandID("BQUFBQUFBQUFBQUFBQUFBQ")
	owner := &otpSendNative{rate: backend, result: mfa.OtpSendResult{CommandID: id, Outcome: identity.CommitOutcomeCommitted, ChallengeID: string(id), DeliveryState: delivery.StateQueued}}
	return OTPSendConfig{Network: base.Network, Service: owner, Rate: limiter, Origin: base.Origin, CallbackURL: base.CallbackURL, Device: base.Device, ActorID: base.ActorID, PolicyRevision: base.PolicyRevision, Now: base.Now, MaximumDuration: base.MaximumDuration}, owner, string(wire), device
}
func otpSendRequest(c OTPSendConfig, body string, device *http.Cookie) *http.Request {
	r := otpRequest(OTPVerifyConfig{Origin: c.Origin}, body, device)
	r.URL.Path = "/v1/mfa/otp-send"
	r.RequestURI = r.URL.RequestURI()
	r.Header.Set("Idempotency-Key", "original-send-key")
	return r
}

func TestOTPSendHTTPClosedKeyedInputAndNoCredentials(t *testing.T) {
	for _, mode := range []string{"queued", "unknown", "conflict", "mismatched-challenge", "source-denied", "source-outage", "send-outage", "missing-key", "duplicate-key", "body-key", "command-override", "destination", "duplicate-json", "origin", "authorization", "variant", "missing-device", "callback", "channel"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, body, device := otpSendFixture(t)
			switch mode {
			case "unknown":
				owner.result.Outcome = identity.CommitOutcomeUnknown
			case "conflict":
				owner.result.Outcome = identity.CommitOutcomeConflict
			case "mismatched-challenge":
				owner.result.ChallengeID = "BgYGBgYGBgYGBgYGBgYGBg"
			case "source-denied":
				owner.fail = true
			case "source-outage":
				owner.rate.fail = 1
			case "send-outage":
				owner.rate.fail = 2
			case "missing-device":
				device = nil
			case "body-key":
				body = strings.TrimSuffix(body, "}") + `,"idempotencyKey":"alternative"}`
			case "command-override":
				body = strings.TrimSuffix(body, "}") + `,"commandID":"AQEBAQEBAQEBAQEBAQEBAQ"}`
			case "destination":
				body = strings.TrimSuffix(body, "}") + `,"destination":"foreign@example.test"}`
			case "duplicate-json":
				body = strings.TrimSuffix(body, "}") + `,"channel":"sms"}`
			case "callback":
				body = strings.Replace(body, c.CallbackURL, "https://foreign.example", 1)
			case "channel":
				body = strings.Replace(body, `"channel":"email"`, `"channel":"push"`, 1)
			}
			h, err := NewOTPSendHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			r := otpSendRequest(c, body, device)
			switch mode {
			case "missing-key":
				r.Header.Del("Idempotency-Key")
			case "duplicate-key":
				r.Header.Add("Idempotency-Key", "another")
			case "origin":
				r.Header.Set("Origin", "https://foreign.example")
			case "authorization":
				r.Header.Set("Authorization", "Bearer override")
			case "variant":
				r.Header.Set("X-MFA-Variant", "enrollment")
			}
			w := httptest.NewRecorder()
			w.Header().Set("Set-Cookie", "injected")
			w.Header().Set("X-MFA-Token", "injected")
			h.ServeHTTP(w, r)
			var out OTPSendResponse
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("X-MFA-Token") != "" || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "native-recipient") {
				t.Fatal("sending leaked credential/destination or cacheable output", mode, w.Code)
			}
			if mode == "queued" {
				if w.Code != 202 || !out.Accepted || out.CommitOutcome != "committed" || out.CommandID != owner.result.CommandID || out.ChallengeID != owner.result.ChallengeID || out.DeliveryState != "queued" || owner.reads != 1 || owner.calls != 1 {
					t.Fatal("owned keyed queue result missing", w.Code)
				}
				want, _ := identity.NewIdempotencyKey([]byte("original-send-key"))
				expected, _ := want.Digest([32]byte{1})
				actual, _ := owner.last.IdempotencyKey.Digest([32]byte{1})
				if actual != expected || owner.last.Channel != delivery.ChannelEmail || owner.last.Cookie.Token() == "" || owner.last.Caller.Request.Action != "identity.mfa.otp-send" || string(owner.last.Caller.Request.Resource.ID) != string(owner.last.ContinuationID) {
					t.Fatal("keyed native sending scope changed")
				}
			} else if w.Code < 400 || out.Accepted || out.ChallengeID != "" || out.DeliveryState != "" {
				t.Fatal("invalid/uncertain send disclosed queued state", mode, w.Code)
			}
			if mode != "queued" && mode != "unknown" && mode != "conflict" && mode != "mismatched-challenge" && owner.calls != 0 {
				t.Fatal("unadmitted request queued a challenge", mode)
			}
		})
	}
}

func TestOTPSendHTTPRequiresActualNativeOwner(t *testing.T) {
	c, _, _, _ := otpSendFixture(t)
	c.Service = (*otpSendNative)(nil)
	if h, err := NewOTPSendHandler(c); err == nil || h != nil {
		t.Fatal("nil owner selected sending")
	}
}

func TestOTPSendHTTPSelectedFeatureHasClosedKeyContract(t *testing.T) {
	c, owner, body, device := otpSendFixture(t)
	feature, err := NewFeature(FeatureConfig{OTPSend: &c})
	if err != nil || len(feature.Operations()) != 1 {
		t.Fatal("explicit sending feature missing", err)
	}
	op := feature.Operations()[0]
	if op.Record.OperationID != "identity.mfa.otp-send" || op.Record.Idempotency != "keyed" || op.Route.Path != "/v1/mfa/otp-send" || op.Wire == nil {
		t.Fatal("sending route/schema/key metadata mismatched")
	}
	var definition map[string]any
	if json.Unmarshal(op.Wire.Definition, &definition) != nil {
		t.Fatal("invalid sending schema")
	}
	schema := definition["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	properties := schema["properties"].(map[string]any)
	if len(properties) != 6 || properties["factorID"] == nil || properties["channel"] == nil || properties["commandID"] != nil || properties["idempotencyKey"] != nil || properties["destination"] != nil || schema["additionalProperties"] != false {
		t.Fatal("send schema allowed domain/key override")
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || len(ops) != 1 {
		t.Fatal("canonical sending composition failed", err)
	}
	w := httptest.NewRecorder()
	ops[0].Handler.ServeHTTP(w, otpSendRequest(c, body, device))
	if w.Code != 202 || owner.calls != 1 {
		t.Fatal("selected sending route did not invoke native owner", w.Code)
	}
}
