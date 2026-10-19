package otphttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	otphttp "github.com/faustbrian/go-identity/http/otp"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/phone"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

// These transport seams do not prove native authentication. The genuine
// enrolled-phone PostgreSQL consumer proves persistence and session usability.
func TestPhoneSigninFeatureSelectsOnlyClosedSMSOperations(t *testing.T) {
	send, generic, sendRequest := sendFixture(t)
	signin, _, signinBody := fixture(t)
	recovery, _, recoveryBody, original := recoveryFixture(t)
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64, AllowNational: true, DefaultRegion: "US"})
	if err != nil {
		t.Fatal(err)
	}
	owner := &phoneSigninOwner{t: t, config: signin, channel: otp.ChannelSMS, kind: identity.IdentifierPhone, send: generic.result}
	signin.Service, signin.Source = owner, owner
	history := &phoneHistoryOwner{t: t, result: original}
	recovery.Service = history
	feature, err := otphttp.NewPhoneSigninFeature(otphttp.PhoneSigninSendConfig{Network: send.Network, Service: owner, Policy: policy, Rate: send.Rate, Origin: send.Origin, FlowCookie: send.FlowCookie, Device: send.Device, ActorID: send.ActorID, PolicyRevision: send.PolicyRevision, Now: send.Now, MaximumDuration: send.MaximumDuration}, signin, recovery)
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Phone", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if json.Unmarshal(doc.JSON(), &document) != nil || len(document["paths"].(map[string]any)) != 3 || owner.sends+owner.sources+owner.attempts+history.calls != 0 {
		t.Fatal("phone selection invoked native work or exposed unrelated paths")
	}
	parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"send", "signin", "recover"} {
		t.Run(mode, func(t *testing.T) {
			r, path, status := request(signinBody), "/v1/phone/signin", 200
			if mode == "send" {
				r, path, status = sendRequest, "/v1/phone/send-signin", 202
				r.Body = io.NopCloser(strings.NewReader(`{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","number":"2025550123"}`))
				r.ContentLength = int64(len(`{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","number":"2025550123"}`))
			}
			if mode == "recover" {
				r, path = recoveryRequest(recoveryBody), "/v1/phone/signin/recover"
			}
			r.URL.Path = path
			r.RequestURI = r.URL.RequestURI()
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != status || (mode != "signin" && (len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "")) {
				t.Fatal("selected phone route failed or disclosed credentials", w.Code)
			}
			if mode == "signin" && (len(w.Result().Cookies()) != 1 || w.Header().Get("X-CSRF-Token") == "") {
				t.Fatal("fresh native result lost its guarded session")
			}
			node := parsed.Raw()
			for _, key := range []string{"paths", path, "post", "responses", strconv.Itoa(status), "content", "application/json", "schema"} {
				var ok bool
				node, ok = node.Lookup(key)
				if !ok {
					t.Fatal("missing actual phone response schema")
				}
			}
			instance, err := parse.JSON(context.Background(), bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
			if err != nil || !report.Valid() {
				t.Fatal("actual phone response violates its wire contract", err)
			}
		})
	}
	if owner.sends != 1 || owner.sources != 1 || owner.attempts != 1 || history.calls != 1 {
		t.Fatal("phone routes did not reach their separate frozen owners exactly once")
	}
	// A selected phone contribution must coexist with the retained email
	// contribution, not merely work when it owns the entire document.
	emailSend, _, _ := sendFixture(t)
	emailSignin, emailOwner, emailBody := fixture(t)
	emailOwner.result = func(_ context.Context, r otp.SigninRequest) (otp.SigninResult, error) {
		return issuance(t, emailSignin, r), nil
	}
	emailRecovery, _, _, _ := recoveryFixture(t)
	emailFeature, err := otphttp.NewEmailSigninFeature(emailSend, emailSignin, emailRecovery)
	if err != nil {
		t.Fatal(err)
	}
	mixed, mixedDoc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Phone and email", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature, emailFeature}})
	if err != nil {
		t.Fatal("phone and retained email features cannot coexist", err)
	}
	if json.Unmarshal(mixedDoc.JSON(), &document) != nil || len(document["paths"].(map[string]any)) != 6 {
		t.Fatal("mixed selection lost a phone or email operation")
	}
	schemes := document["components"].(map[string]any)["securitySchemes"].(map[string]any)
	if len(schemes) != 4 || schemes["IdentityPhoneOTPOriginalFlow"].(map[string]any)["name"] != "__Host-identity_flow" || schemes["IdentityPhoneOTPBrowserDevice"].(map[string]any)["name"] != "__Host-identity_device" {
		t.Fatal("phone scheme namespace changed actual browser custody")
	}
	for path, raw := range document["paths"].(map[string]any) {
		prefix := "IdentityOTP"
		if strings.HasPrefix(path, "/v1/phone/") {
			prefix = "IdentityPhoneOTP"
		}
		for _, requirement := range raw.(map[string]any)["post"].(map[string]any)["security"].([]any) {
			for name := range requirement.(map[string]any) {
				if !strings.HasPrefix(name, prefix) || schemes[name] == nil {
					t.Fatal("mixed operation references a missing or foreign custody scheme")
				}
			}
		}
	}
	for _, email := range []bool{false, true} {
		r := request(signinBody)
		if email {
			r = request(emailBody)
		} else {
			r.URL.Path = "/v1/phone/signin"
			r.RequestURI = r.URL.RequestURI()
		}
		w := httptest.NewRecorder()
		mixed.ServeHTTP(w, r)
		if w.Code != 200 || len(w.Result().Cookies()) != 1 || w.Header().Get("X-CSRF-Token") == "" {
			t.Fatal("mixed selection lost native email or phone credential delivery", w.Code)
		}
	}
	if owner.attempts != 2 || emailOwner.attempts != 1 {
		t.Fatal("mixed dispatch reached the wrong signin owner")
	}
	off, offDoc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Phone", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	r := request(signinBody)
	r.URL.Path = "/v1/phone/signin"
	w := httptest.NewRecorder()
	off.ServeHTTP(w, r)
	if w.Code != 404 || strings.Contains(string(offDoc.JSON()), "phone.signin") || owner.attempts != 2 {
		t.Fatal("unselected phone feature retained execution or metadata")
	}
}
