package oauthserverhttp

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/faustbrian/go-oauth-server/device"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

func deviceWireInstance(t *testing.T, wire *identityhttp.WireOperation, location []string, body []byte, direction validate.InstanceDirection, valid bool) {
	t.Helper()
	var definition any
	if err := json.Unmarshal(wire.Definition, &definition); err != nil {
		t.Fatal(err)
	}
	schemes := map[string]any{}
	for _, component := range wire.SecuritySchemes {
		var value any
		if err := json.Unmarshal(component.Definition, &value); err != nil {
			t.Fatal(err)
		}
		schemes[component.Name] = value
	}
	doc, err := json.Marshal(map[string]any{"openapi": "3.1.1", "info": map[string]any{"title": "Device wire", "version": "1"}, "paths": map[string]any{"/operation": map[string]any{"post": definition}}, "components": map[string]any{"securitySchemes": schemes}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(doc), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	schema := parsed.Raw()
	for _, name := range append([]string{"paths", "/operation", "post"}, location...) {
		var ok bool
		schema, ok = schema.Lookup(name)
		if !ok {
			t.Fatal("actual channel has no declared schema", name)
		}
	}
	instance, err := parse.JSON(t.Context(), bytes.NewReader(body), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	report, err := validate.SchemaInstance(t.Context(), parsed, schema, instance, validate.InstanceOptions{Direction: direction})
	if err != nil || report.Valid() != valid {
		t.Fatal("wire schema acceptance differs from selected handler contract", valid, err)
	}
}

func deviceWireResponse(t *testing.T, wire *identityhttp.WireOperation, w *httptest.ResponseRecorder) {
	t.Helper()
	deviceWireInstance(t, wire, []string{"responses", strconv.Itoa(w.Code), "content", "application/json", "schema"}, w.Body.Bytes(), validate.DirectionResponse, true)
}

func TestDeviceWireValidatesActualConsentProjectionsAndDenials(t *testing.T) {
	c := consentConfig(t)
	now := c.Now()
	for _, action := range []string{"device-inspect", "device-approve", "device-deny"} {
		wire, err := deviceOperationWire(action, &c, true)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		r := consentRequest(action, "")
		if action == "device-inspect" {
			writeDevicePrompt(w, r, now, oauth.DevicePrompt{ClientID: "client", ClientDisplay: "Living room", UserCode: "BCDF-GHJK", Resource: "https://resource.example", Scopes: []string{"identity:read"}, ExpiresAt: now.Add(time.Minute)}, nil)
		} else {
			writeDeviceConsentCompletion(w, r, action, oauth.Completion{Outcome: identity.CommitOutcomeCommitted, CommandID: "AAAAAAAAAAAAAAAAAAAAAg"}, nil)
		}
		deviceWireResponse(t, wire, w)
		if action == "device-deny" {
			w = httptest.NewRecorder()
			writeDeviceConsentCompletion(w, r, action, oauth.Completion{Outcome: identity.CommitOutcomeCommitted, Replayed: true}, nil)
			assertDeviceResponse(t, w, 200, map[string]any{"state": "denied", "completion": map[string]any{"outcome": "committed", "replayed": true}})
			deviceWireResponse(t, wire, w)
		}
		for _, failure := range []error{device.ErrAccessDenied, device.ErrUnavailable, protocolFailure{status: 403, code: "origin_or_csrf_denied"}} {
			w = httptest.NewRecorder()
			rejectDevice(w, r, failure)
			deviceWireResponse(t, wire, w)
		}
	}
}

func TestDeviceWireValidatesActualProtocolCodeAndTokenProjections(t *testing.T) {
	now := time.Unix(1800000000, 0)
	authorization, err := deviceOperationWire("device-authorize", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	r := deviceAuthorizationRequest("client_id=screen")
	w := httptest.NewRecorder()
	writeDeviceAuthorization(w, r, now, deviceResponseAuthorization(t, now), nil)
	deviceWireResponse(t, authorization, w)
	for _, workload := range []bool{false, true} {
		wire := tokenWireWithDevice(workload, true)
		for _, refresh := range []bool{false, true} {
			w = httptest.NewRecorder()
			writeDevicePoll(w, r, now, deviceResponsePollResult(t, now, refresh), nil)
			deviceWireResponse(t, wire, w)
		}
		for _, failure := range []error{device.ErrAuthorizationPending, device.ErrSlowDown, device.ErrExpiredToken, device.ErrAccessDenied, oauth.ErrInvalidClient, protocolFailure{status: 429, code: "temporarily_unavailable", retry: time.Second}} {
			w = httptest.NewRecorder()
			rejectDevice(w, r, failure)
			deviceWireResponse(t, wire, w)
		}
	}
}

func TestDeviceWireConsentBodiesRemainClosedAndRequireExplicitComparison(t *testing.T) {
	c := consentConfig(t)
	for _, tc := range []struct {
		action, media, body string
		valid               bool
	}{
		{"device-approve", "application/json", `{"user_code":"bcdfghjk","confirmed_user_code":"BCDF-GHJK"}`, true},
		{"device-approve", "application/json", `{"user_code":"BCDF-GHJK"}`, false},
		{"device-approve", "application/json", `{"user_code":"BCDF-GHJK","confirmed_user_code":"BCDF-GHJK","subject_id":"other"}`, false},
		{"device-deny", "application/json", `{"user_code":"BCDF-GHJK"}`, true},
		{"device-deny", "application/json", `{"user_code":"BCDF-GHJK","confirmed_user_code":"BCDF-GHJK"}`, false},
		{"device-deny", "application/json", `{"user_code":"BCDF-GHJK","csrf_token":"` + strings.Repeat("A", 43) + `"}`, false},
		{"device-deny", "application/x-www-form-urlencoded", `{"user_code":"BCDF-GHJK","csrf_token":"` + strings.Repeat("A", 43) + `"}`, true},
	} {
		wire, err := deviceOperationWire(tc.action, &c, true)
		if err != nil {
			t.Fatal(err)
		}
		deviceWireInstance(t, wire, []string{"requestBody", "content", tc.media, "schema"}, []byte(tc.body), validate.DirectionRequest, tc.valid)
	}
}

func TestDeviceWireTokenVariantsExcludeOtherGrantsAndCredentialOverrides(t *testing.T) {
	for _, workload := range []bool{false, true} {
		wire := tokenWireWithDevice(workload, true)
		for _, tc := range []struct {
			body  string
			valid bool
		}{
			{`{"grant_type":"` + device.GrantType + `","device_code":"` + strings.Repeat("A", 43) + `","client_id":"screen"}`, true},
			{`{"grant_type":"` + device.GrantType + `","device_code":"` + strings.Repeat("A", 43) + `"}`, true},
			{`{"grant_type":"` + device.GrantType + `","device_code":"` + strings.Repeat("A", 43) + `","scope":"identity:read"}`, false},
			{`{"grant_type":"` + device.GrantType + `","device_code":"` + strings.Repeat("A", 43) + `","client_secret":"private"}`, false},
			{`{"grant_type":"refresh_token","refresh_token":"private"}`, false},
			{`{"grant_type":"client_credentials"}`, workload},
		} {
			deviceWireInstance(t, wire, []string{"requestBody", "content", "application/x-www-form-urlencoded", "schema"}, []byte(tc.body), validate.DirectionRequest, tc.valid)
		}
	}
}

func TestDeviceWireAuthorizationPreservesNativeEmptyDefaultsAndExtensions(t *testing.T) {
	wire, err := deviceOperationWire("device-authorize", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body  string
		valid bool
	}{
		{`{"client_id":"screen","scope":"","resource":""}`, true},
		{`{"client_id":"screen","future":"ignored"}`, true},
		{`{"client_id":"screen","device_code":"private"}`, false},
		{`{"client_id":"screen","client_secret":"private"}`, false},
		{`{"client_id":"screen","grant_type":"client_credentials"}`, false},
	} {
		deviceWireInstance(t, wire, []string{"requestBody", "content", "application/x-www-form-urlencoded", "schema"}, []byte(tc.body), validate.DirectionRequest, tc.valid)
	}
}

func TestDeviceWireUnknownActionAndMissingCookiePolicyFailClosed(t *testing.T) {
	for _, action := range []string{"unknown", "device-inspect", "device-approve", "device-deny"} {
		if wire, err := deviceOperationWire(action, nil, true); err == nil || wire != nil {
			t.Fatal("unselected browser policy acquired a wire definition")
		}
	}
	if wire, err := deviceOperationWire("device-inspect", &DeviceConsentConfig{}, true); err == nil || wire != nil {
		t.Fatal("invalid cookie selection acquired a browser security component")
	}
}
