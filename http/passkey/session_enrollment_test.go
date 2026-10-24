package passkeyhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	passkey "github.com/faustbrian/go-passkey"
)

func TestSessionEnrollmentRequiresExplicitActualOwners(t *testing.T) {
	if _, err := NewSessionEnrollmentOptionsHandler(SessionEnrollmentConfig{}); err == nil {
		t.Fatal("session enrollment selected without actual owners")
	}
	if _, err := NewSessionEnrollmentVerifyHandler(SessionEnrollmentConfig{}); err == nil {
		t.Fatal("session enrollment completion selected without actual owners")
	}
	if _, err := NewFeature(FeatureConfig{SessionEnrollment: &SessionEnrollmentConfig{}}); err == nil {
		t.Fatal("feature accepted absent enrollment owners")
	}
}

// Only the borrowed native workflow is doubled. The real SessionService,
// synchronizer, ingress, pipeline and shared limiter execute unchanged. Actual
// opaque fresh options and protocol verification belong to the Reference PG
// consumer, rather than fabricated protocol custody in this transport test.
type observedSessionEnrollment struct {
	assertions, registrations, sources, completions int
	request                                         passkey.SessionEnrollmentRequestSpec
	key                                             identity.IdempotencyKey
	authorization                                   passkey.SessionEnrollmentAuthorizationSpec
	completion                                      passkey.SessionEnrollmentCompletionSpec
	assertionResult                                 passkey.KeyedAssertionOptionsResult
	registrationResult                              passkey.KeyedRegistrationOptionsResult
	result                                          passkey.SessionEnrollmentResult
	ceiling                                         time.Time
	source                                          passkey.CeremonyRateSource
	err, sourceErr                                  error
	afterSource                                     func()
}

func (o *observedSessionEnrollment) EnrollmentAssertionOptions(_ context.Context, r passkey.SessionEnrollmentOptionsRequest) (passkey.KeyedAssertionOptionsResult, error) {
	o.assertions++
	o.request, _ = r.SessionEnrollmentRequest.Bindings()
	o.key = r.IdempotencyKey
	return o.assertionResult, o.err
}
func (o *observedSessionEnrollment) RegistrationOptionsForDelivery(_ context.Context, r passkey.SessionEnrollmentAuthorization) (passkey.KeyedRegistrationOptionsResult, time.Time, error) {
	o.registrations++
	o.authorization, _ = r.Bindings()
	o.request, _ = o.authorization.SessionEnrollmentRequest.Bindings()
	o.key = o.authorization.IdempotencyKey
	return o.registrationResult, o.ceiling, o.err
}
func (o *observedSessionEnrollment) SessionRegistrationRateSource(_ context.Context, r passkey.SessionEnrollmentRequest, _ string) (passkey.CeremonyRateSource, error) {
	o.sources++
	o.request, _ = r.Bindings()
	if o.afterSource != nil {
		o.afterSource()
	}
	return o.source, o.sourceErr
}

func TestSessionEnrollmentAdmissionCannotSurviveRateClosureOrAuthorityExpiry(t *testing.T) {
	for _, mode := range []string{"options-rate", "verify-rate", "source-expiry", "inactive", "foreign-session"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, reader, cookie, csrf := sessionEnrollmentFixture(t)
			now := c.Now()
			c.Now = func() time.Time { return now }
			owner.sourceErr = nil
			owner.source = passkey.CeremonyRateSource{CeremonyID: "AAAAAAAAAAAAAAAAAAAAAg", Kind: passkey.RateSourceUser, UserID: "user-a", Lifetime: 5 * time.Minute}
			operation, body := "register-options", enrollmentAssertionWire
			if mode == "verify-rate" || mode == "source-expiry" {
				operation, body = "register-verify", enrollmentCompleteWire
			}
			switch mode {
			case "source-expiry":
				owner.afterSource = func() { now = now.Add(21 * time.Second) }
			case "inactive":
				reader.observation.Active = false
			case "foreign-session":
				reader.observation.Current = session.AuthoritySnapshot{}
			}
			h, err := NewSessionEnrollmentOptionsHandler(c)
			if operation == "register-verify" {
				h, err = NewSessionEnrollmentVerifyHandler(c)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "options-rate" {
				_ = c.OptionsRate.Close()
			}
			if mode == "verify-rate" {
				_ = c.VerificationRate.Close()
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, enrollmentRequest(operation, body, cookie, csrf))
			if w.Code < 400 || owner.assertions+owner.registrations+owner.completions != 0 {
				t.Fatal("expired/closed authority reached native mutation", mode, w.Code)
			}
			if mode != "source-expiry" && owner.sources != 0 {
				t.Fatal("denied authority reached native source")
			}
		})
	}
}
func (o *observedSessionEnrollment) Register(_ context.Context, r passkey.SessionEnrollmentCompletion) (passkey.SessionEnrollmentResult, error) {
	o.completions++
	o.completion, _ = r.Bindings()
	o.request, _ = o.completion.SessionEnrollmentRequest.Bindings()
	return o.result, o.err
}

const enrollmentAssertionWire = `{"mode":"session","phase":"assertion","label":"Additional key"}`
const enrollmentRegistrationWire = `{"mode":"session","phase":"registration","label":"Additional key","ceremonyID":"AAAAAAAAAAAAAAAAAAAAAQ","response":{"id":"untrusted"}}`
const enrollmentCompleteWire = `{"mode":"session","label":"Additional key","commandID":"AAAAAAAAAAAAAAAAAAAAAw","ceremonyID":"AAAAAAAAAAAAAAAAAAAAAg","response":{"id":"untrusted"}}`

func sessionEnrollmentFixture(t *testing.T) (SessionEnrollmentConfig, *observedSessionEnrollment, *observedSession, *http.Cookie, string) {
	t.Helper()
	c, _, reader, cookie, _, csrf := registrationFixture(t)
	owner := &observedSessionEnrollment{err: identity.ForbiddenError{}, sourceErr: identity.ForbiddenError{}}
	return SessionEnrollmentConfig{Network: c.Network, Sessions: c.Sessions, Service: owner, OptionsRate: c.OptionsRate, VerificationRate: c.VerificationRate, Origin: c.Origin, SessionCookie: c.SessionCookie, CSRFKeys: c.CSRFKeys, PolicyRevision: c.PolicyRevision, Audience: c.Audience, Now: c.Now, MaximumDuration: c.MaximumDuration}, owner, reader, cookie, csrf
}
func enrollmentRequest(operation, body string, cookie *http.Cookie, csrf string) *http.Request {
	r := registrationRequest(operation, body, cookie, nil, csrf)
	if strings.Contains(body, `"phase":"registration"`) {
		r.Header.Set("Idempotency-Key", "original-enrollment-registration")
	}
	return r
}

func enrollmentObservation(t *testing.T, stage int, outcome identity.CommitOutcome) identity.CommandResult {
	t.Helper()
	r := updateObservation(t, outcome).Receipt
	r.Binding.OperationID = "identity.passkey.register-options"
	r.Binding.SchemaID = "identity.passkey.register-options.session-assertion-options-v1"
	if stage == 1 {
		r.Binding.SchemaID = "identity.passkey.register-options.session-registration-options-v1"
	}
	if stage == 2 {
		r.Binding.OperationID = "identity.passkey.register-verify"
		r.Binding.SchemaID = "identity.passkey.register-verify.session-registration-v1"
	}
	r.Binding.RecordID = string(r.Binding.CommandID)
	r.Feature.Operation.OperationID, r.Feature.Operation.SchemaID = r.Binding.OperationID, r.Binding.SchemaID
	if outcome == identity.CommitOutcomeCommitted {
		r.Feature.BeforeVersion, r.Feature.AfterVersion = 0, 1
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSessionEnrollmentForwardsOnlyOriginalCurrentSessionIntent(t *testing.T) {
	for stage, body := range []string{enrollmentAssertionWire, enrollmentRegistrationWire, enrollmentCompleteWire} {
		t.Run(fmt.Sprint(stage), func(t *testing.T) {
			c, owner, reader, cookie, csrf := sessionEnrollmentFixture(t)
			operation := "register-options"
			h, err := NewSessionEnrollmentOptionsHandler(c)
			if stage == 2 {
				operation = "register-verify"
				h, err = NewSessionEnrollmentVerifyHandler(c)
			}
			if err != nil || reader.reads != 0 {
				t.Fatal("construction performed IO", err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, enrollmentRequest(operation, body, cookie, csrf))
			if w.Code != 403 {
				t.Fatal("native denial changed", w.Code, w.Body.String())
			}
			if stage == 0 && owner.assertions != 1 || stage == 1 && owner.registrations != 1 || stage == 2 && (owner.sources != 1 || owner.completions != 0) {
				t.Fatal("wrong native boundary")
			}
			r := owner.request
			if r.Credential.Kind() != session.CredentialCookie || r.CSRFToken == (session.CSRFToken{}) || r.Caller.Request.Subject.ID != "user-a" || r.Caller.Request.Resource.ID != "user-a" || r.Caller.Request.Action != authorization.Action("identity.passkey."+operation) || r.Label != "Additional key" || r.Origin != string(c.Origin) || r.Network != "198.51.100.7" {
				t.Fatal("current custody or intent replaced")
			}
			if stage < 2 && owner.key == (identity.IdempotencyKey{}) {
				t.Fatal("original key lost")
			}
			if stage == 1 && (owner.authorization.CeremonyID != "AAAAAAAAAAAAAAAAAAAAAQ" || string(owner.authorization.Response) != `{"id":"untrusted"}`) {
				t.Fatal("original assertion changed")
			}
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("enrollment issued authentication")
			}
		})
	}
}

func TestSessionEnrollmentClosedBodiesAndHeadersDenyBeforeNative(t *testing.T) {
	for stage, original := range []string{enrollmentAssertionWire, enrollmentRegistrationWire, enrollmentCompleteWire} {
		for _, mode := range []string{"proofID", "tenantID", "userID", "rpID", "remember", "idempotencyKey", "csrfToken", "cookie", "phase", "body-command", "no-mode", "null-label", "oversized-label", "control-label", "duplicate", "no-key", "duplicate-key", "completion-key", "authorization", "no-cookie", "no-csrf", "wrong-csrf", "origin", "query", "trailer", "trailing", "encoding", "length"} {
			if stage == 2 && (mode == "no-key" || mode == "duplicate-key" || mode == "body-command") || stage != 2 && mode == "completion-key" {
				continue
			}
			t.Run(fmt.Sprint(stage)+"/"+mode, func(t *testing.T) {
				c, owner, _, cookie, csrf := sessionEnrollmentFixture(t)
				body := original
				switch mode {
				case "proofID", "tenantID", "userID", "rpID", "remember", "idempotencyKey", "csrfToken", "cookie":
					body = strings.Replace(body, `{`, `{"`+mode+`":"override",`, 1)
				case "phase":
					if stage == 2 {
						body = strings.Replace(body, `{`, `{"phase":"registration",`, 1)
					} else {
						body = strings.Replace(body, `"phase":`, `"phase":null,"unused":`, 1)
					}
				case "body-command":
					body = strings.Replace(body, `{`, `{"commandID":"AAAAAAAAAAAAAAAAAAAAAw",`, 1)
				case "no-mode":
					body = strings.Replace(body, `"mode":"session",`, "", 1)
				case "null-label":
					body = strings.Replace(body, `"Additional key"`, `null`, 1)
				case "oversized-label":
					body = strings.Replace(body, `Additional key`, strings.Repeat("x", 129), 1)
				case "control-label":
					body = strings.Replace(body, `Additional key`, `bad\u0000label`, 1)
				case "duplicate":
					body = strings.Replace(body, `{`, `{"mode":"session",`, 1)
				case "trailing":
					body += `{}`
				}
				operation := "register-options"
				h, err := NewSessionEnrollmentOptionsHandler(c)
				if stage == 2 {
					operation = "register-verify"
					h, err = NewSessionEnrollmentVerifyHandler(c)
				}
				if err != nil {
					t.Fatal(err)
				}
				r := enrollmentRequest(operation, body, cookie, csrf)
				switch mode {
				case "no-key":
					r.Header.Del("Idempotency-Key")
				case "duplicate-key":
					r.Header.Add("Idempotency-Key", "other")
				case "completion-key":
					r.Header.Set("Idempotency-Key", "forbidden")
				case "authorization":
					r.Header.Set("Authorization", "Bearer other")
				case "no-cookie":
					r.Header.Del("Cookie")
				case "no-csrf":
					r.Header.Del("X-CSRF-Token")
				case "wrong-csrf":
					r.Header.Set("X-CSRF-Token", strings.Repeat("A", 42)+"E")
				case "origin":
					r.Header.Set("Origin", "https://foreign.example")
				case "query":
					r.URL.RawQuery = "mode=session"
				case "trailer":
					r.Trailer = http.Header{"Idempotency-Key": []string{"other"}}
				case "encoding":
					r.Header.Set("Content-Encoding", "gzip")
				case "length":
					r.ContentLength++
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code < 400 || owner.assertions+owner.registrations+owner.sources+owner.completions != 0 {
					t.Fatal("invalid custody reached native owner", w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestSessionEnrollmentSourceMustAuthenticateExactUserAndChallenge(t *testing.T) {
	for _, mode := range []string{"denied", "user", "challenge", "kind", "identifier", "flow", "lifetime", "valid"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, _, cookie, csrf := sessionEnrollmentFixture(t)
			owner.source = passkey.CeremonyRateSource{CeremonyID: "AAAAAAAAAAAAAAAAAAAAAg", Kind: passkey.RateSourceUser, UserID: "user-a", Lifetime: 5 * time.Minute}
			owner.sourceErr = nil
			switch mode {
			case "denied":
				owner.sourceErr = identity.ForbiddenError{}
			case "user":
				owner.source.UserID = "foreign"
			case "challenge":
				owner.source.CeremonyID = "AAAAAAAAAAAAAAAAAAAAAQ"
			case "kind":
				owner.source.Kind = passkey.RateSourceAnonymousFlow
			case "identifier":
				owner.source.Identifier = "foreign@example.invalid"
			case "flow":
				owner.source.AnonymousFlowID = "other"
			case "lifetime":
				owner.source.Lifetime = time.Minute
			}
			h, err := NewSessionEnrollmentVerifyHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, enrollmentRequest("register-verify", enrollmentCompleteWire, cookie, csrf))
			if owner.sources != 1 || mode == "valid" && owner.completions != 1 || mode != "valid" && owner.completions != 0 || w.Code < 400 {
				t.Fatal("unauthenticated source admitted completion", mode, w.Code)
			}
			if mode == "valid" && (owner.completion.CommandID != "AAAAAAAAAAAAAAAAAAAAAw" || owner.completion.CeremonyID != "AAAAAAAAAAAAAAAAAAAAAg" || string(owner.completion.Response) != `{"id":"untrusted"}`) {
				t.Fatal("completion correlation changed")
			}
		})
	}
}

func TestSessionEnrollmentRetriesAndFailuresKeepOriginalDurabilityOnly(t *testing.T) {
	for stage := range 3 {
		for _, mode := range []string{"replay", "unknown", "committed-error", "foreign", "wrong-schema", "wrong-owner", "wrong-version", "missing-fresh-options"} {
			t.Run(fmt.Sprint(stage)+"/"+mode, func(t *testing.T) {
				c, owner, _, cookie, csrf := sessionEnrollmentFixture(t)
				outcome := identity.CommitOutcomeCommitted
				if mode == "unknown" {
					outcome = identity.CommitOutcomeUnknown
				}
				receipt := enrollmentObservation(t, stage, outcome)
				if mode == "foreign" {
					receipt.Binding.UserID = "foreign"
				}
				if mode == "wrong-schema" {
					receipt.Binding.SchemaID = "identity.passkey.update.native-v1"
				}
				if mode == "wrong-owner" {
					receipt.Feature.Operation.Owner = "foreign"
				}
				if mode == "wrong-version" {
					receipt.Feature.AfterVersion = 2
				}
				owner.err, owner.sourceErr = nil, nil
				if mode == "unknown" || mode == "committed-error" {
					owner.err = errors.New("private-native-error")
				}
				owner.source = passkey.CeremonyRateSource{CeremonyID: "AAAAAAAAAAAAAAAAAAAAAg", Kind: passkey.RateSourceUser, UserID: "user-a", Lifetime: 5 * time.Minute}
				replay := mode != "missing-fresh-options"
				owner.assertionResult = passkey.KeyedAssertionOptionsResult{CommandID: receipt.Binding.CommandID, Receipt: receipt, Replayed: replay}
				owner.registrationResult = passkey.KeyedRegistrationOptionsResult{CommandID: receipt.Binding.CommandID, Receipt: receipt, Replayed: replay}
				owner.result = passkey.NewSessionEnrollmentResult(passkey.SessionEnrollmentResultSpec{CommandID: receipt.Binding.CommandID, Receipt: receipt, Outcome: outcome, Replayed: replay})
				operation, body := "register-options", enrollmentAssertionWire
				h, err := NewSessionEnrollmentOptionsHandler(c)
				if stage == 1 {
					body = enrollmentRegistrationWire
				}
				if stage == 2 {
					operation, body = "register-verify", enrollmentCompleteWire
					h, err = NewSessionEnrollmentVerifyHandler(c)
				}
				if err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, enrollmentRequest(operation, body, cookie, csrf))
				want := 503
				if mode == "replay" || stage == 2 && mode == "missing-fresh-options" {
					want = 200
				}
				if w.Code != want {
					t.Fatal("unexpected native result", w.Code, w.Body.String())
				}
				var got map[string]any
				if json.Unmarshal(w.Body.Bytes(), &got) != nil {
					t.Fatal("non-JSON result")
				}
				if mode == "unknown" && got["commitOutcome"] != "unknown" || mode == "committed-error" && got["commitOutcome"] != "committed" {
					t.Fatal("native durability lost", w.Body.String())
				}
				for _, field := range []string{"options", "credential", "private-native-error"} {
					if strings.Contains(w.Body.String(), field) {
						t.Fatal("historical secret disclosed", field)
					}
				}
				if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
					t.Fatal("native recovery issued authentication")
				}
			})
		}
	}
}

func TestSessionEnrollmentSelectionKeepsSignupSeparateAndLegacyExclusive(t *testing.T) {
	c, owner, _, cookie, csrf := sessionEnrollmentFixture(t)
	legacy, _, _, _, _, _ := registrationFixture(t)
	if _, err := NewFeature(FeatureConfig{SessionEnrollment: &c, Registration: &legacy}); err == nil {
		t.Fatal("two enrollment owners selected")
	}
	signup, signupOwner, flow, device := signupFixture(t)
	signup.OptionsRate, signup.VerificationRate = c.OptionsRate, c.VerificationRate
	f, err := NewFeature(FeatureConfig{SessionEnrollment: &c, Signup: &signup})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil || len(ops) != 2 {
		t.Fatal("canonical registration pair duplicated", err)
	}
	for _, op := range ops {
		if op.Route.CSRF.Mode != identityhttp.CSRFVariantOriginSessionState {
			t.Fatal("variant CSRF metadata missing")
		}
	}
	h, document, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}, ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(document.JSON()), `"proofID":`) || !strings.Contains(string(document.JSON()), `"session"`) || !strings.Contains(string(document.JSON()), `"signup"`) {
		t.Fatal("selected schemas advertise different variants")
	}
	for _, body := range []string{enrollmentAssertionWire, " \n" + enrollmentAssertionWire + "\n "} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, enrollmentRequest("register-options", body, cookie, csrf))
		if w.Code != 403 || signupOwner.options != 0 {
			t.Fatal("session branch fell back", w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signupRequest("register-options", `{"mode":"signup","flowID":"AAAAAAAAAAAAAAAAAAAAAQ"}`, flow, device))
	if w.Code != 403 || signupOwner.options != 1 || owner.assertions != 2 {
		t.Fatal("signup dispatched to session owner", w.Code)
	}
	for _, body := range []string{`{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"}`, `{"mode":"unknown"}`, `{"mode":"session","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","phase":"assertion"}`} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, enrollmentRequest("register-options", body, cookie, csrf))
		if w.Code != 400 || owner.assertions != 2 || signupOwner.options != 1 {
			t.Fatal("unsupported registration variant reached native")
		}
	}
	for _, mutate := range []func(*SignupConfig){func(c *SignupConfig) { c.Origin = "https://other.example" }, func(c *SignupConfig) { c.OptionsRate = nil }, func(c *SignupConfig) { c.Network.MaximumForwardedHops++ }} {
		bad := signup
		mutate(&bad)
		if _, err := NewFeature(FeatureConfig{SessionEnrollment: &c, Signup: &bad}); err == nil {
			t.Fatal("conflicting ingress/rate identities selected")
		}
	}
	for _, value := range []any{c, SessionEnrollmentState{}, struct{ private SessionEnrollmentState }{}} {
		if strings.Contains(fmt.Sprintf("%+v", value), "tenant.example") || strings.Contains(fmt.Sprintf("%#v", value), "tenant.example") {
			t.Fatal("enclosing diagnostics exposed custody")
		}
	}
	for _, value := range []any{c, SessionEnrollmentState{}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit custody export")
		}
	}
}

func TestSessionEnrollmentFreshCompletionExposesOnlySafeMetadataAfterHooks(t *testing.T) {
	for _, mode := range []string{"fresh", "no-metadata", "foreign-metadata", "replayed-metadata", "expired-session", "append"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, _, cookie, csrf := sessionEnrollmentFixture(t)
			now := c.Now()
			c.Now = func() time.Time { return now }
			receipt := enrollmentObservation(t, 2, identity.CommitOutcomeCommitted)
			out := passkey.SessionEnrollmentResultSpec{CommandID: receipt.Binding.CommandID, Receipt: receipt, Outcome: receipt.Outcome, Credential: &passkey.CredentialMetadata{ReferenceID: string(receipt.Binding.CommandID), Version: 1, State: "active", Label: "Additional key", CreatedAt: now}}
			if mode == "no-metadata" {
				out.Credential = nil
			}
			if mode == "foreign-metadata" {
				out.Credential.ReferenceID = "foreign"
			}
			if mode == "replayed-metadata" {
				out.Replayed = true
			}
			owner.result, owner.err, owner.sourceErr = passkey.NewSessionEnrollmentResult(out), nil, nil
			owner.source = passkey.CeremonyRateSource{CeremonyID: "AAAAAAAAAAAAAAAAAAAAAg", Kind: passkey.RateSourceUser, UserID: "user-a", Lifetime: 5 * time.Minute}
			h, err := NewSessionEnrollmentVerifyHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{transportHook(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				next.ServeHTTP(w, r)
				if mode == "expired-session" {
					now = now.Add(21 * time.Second)
				}
				if mode == "append" {
					_, _ = w.Write([]byte("private-hook-bytes"))
				}
				w.Header().Set("Set-Cookie", "injected=forbidden")
				w.Header().Set("X-CSRF-Token", "injected")
			})})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, enrollmentRequest("register-verify", enrollmentCompleteWire, cookie, csrf))
			want := 503
			if mode == "fresh" || mode == "no-metadata" {
				want = 200
			}
			if w.Code != want {
				t.Fatal("invalid final delivery", w.Code, w.Body.String())
			}
			var got map[string]any
			if json.Unmarshal(w.Body.Bytes(), &got) != nil || got["commitOutcome"] != "committed" || got["commandID"] != string(out.CommandID) {
				t.Fatal("acknowledged commitment lost")
			}
			if mode == "fresh" && got["credential"] == nil {
				t.Fatal("fresh safe metadata missing")
			}
			if mode != "fresh" && got["credential"] != nil || strings.Contains(w.Body.String(), "private-hook") || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("forbidden response custody leaked")
			}
		})
	}
}

func TestSessionEnrollmentWireMatchesRuntimeSelectionAndOriginalMetadata(t *testing.T) {
	for _, combined := range []bool{false, true} {
		t.Run(fmt.Sprint(combined), func(t *testing.T) {
			c, owner, _, cookie, csrf := sessionEnrollmentFixture(t)
			selection := FeatureConfig{SessionEnrollment: &c}
			if combined {
				signup, _, _, _ := signupFixture(t)
				signup.OptionsRate, signup.VerificationRate = c.OptionsRate, c.VerificationRate
				selection.Signup = &signup
			}
			f, err := NewFeature(selection)
			if err != nil {
				t.Fatal(err)
			}
			h, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
			if err != nil {
				t.Fatal(err)
			}
			if !combined && (strings.Contains(string(document.JSON()), "__Host-identity_device") || strings.Contains(string(document.JSON()), "__Host-identity_flow") || strings.Contains(string(document.JSON()), `"proofID":`)) {
				t.Fatal("unselected authority advertised")
			}
			parsed, err := openapi.ParseJSON(t.Context(), strings.NewReader(string(document.JSON())), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			check := func(operation, wire string, response, expected bool) {
				t.Helper()
				keys := []string{"paths", "/v1/passkey/" + operation, "post", "requestBody", "content", "application/json", "schema"}
				if response {
					keys = []string{"paths", "/v1/passkey/" + operation, "post", "responses", "200", "content", "application/json", "schema"}
				}
				node := parsed.Raw()
				for _, key := range keys {
					var ok bool
					node, ok = node.Lookup(key)
					if !ok {
						t.Fatal("missing wire", key)
					}
				}
				instance, err := parse.JSON(t.Context(), strings.NewReader(wire), parse.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				direction := validate.DirectionRequest
				if response {
					direction = validate.DirectionResponse
				}
				report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{Direction: direction})
				if err != nil || report.Valid() != expected {
					t.Fatal("runtime/schema disagreement", operation, wire, err)
				}
			}
			for stage, body := range []string{enrollmentAssertionWire, enrollmentRegistrationWire, enrollmentCompleteWire} {
				operation := "register-options"
				if stage == 2 {
					operation = "register-verify"
				}
				if stage > 0 {
					response := `{"id":"AQ","rawId":"AQ","type":"public-key","response":{"clientDataJSON":"AQ","authenticatorData":"AQ","signature":"AQ"}}`
					if stage == 2 {
						response = `{"id":"AQ","rawId":"AQ","type":"public-key","response":{"clientDataJSON":"AQ","attestationObject":"AQ"}}`
					}
					body = strings.Replace(body, `{"id":"untrusted"}`, response, 1)
				}
				check(operation, body, false, true)
				for _, forbidden := range []string{"proofID", "userID", "flowID", "idempotencyKey", "remember"} {
					check(operation, strings.Replace(body, `{`, `{"`+forbidden+`":"override",`, 1), false, false)
				}
				if stage == 2 {
					check(operation, strings.Replace(body, `{`, `{"phase":"registration",`, 1), false, false)
				}
				receipt := enrollmentObservation(t, stage, identity.CommitOutcomeCommitted)
				owner.err, owner.sourceErr = nil, nil
				owner.assertionResult = passkey.KeyedAssertionOptionsResult{CommandID: receipt.Binding.CommandID, Receipt: receipt, Replayed: true}
				owner.registrationResult = passkey.KeyedRegistrationOptionsResult{CommandID: receipt.Binding.CommandID, Receipt: receipt, Replayed: true}
				owner.result = passkey.NewSessionEnrollmentResult(passkey.SessionEnrollmentResultSpec{CommandID: receipt.Binding.CommandID, Receipt: receipt, Outcome: receipt.Outcome, Replayed: true})
				owner.source = passkey.CeremonyRateSource{CeremonyID: "AAAAAAAAAAAAAAAAAAAAAg", Kind: passkey.RateSourceUser, UserID: "user-a", Lifetime: 5 * time.Minute}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, enrollmentRequest(operation, body, cookie, csrf))
				if w.Code != 200 {
					t.Fatal("actual replay rejected", w.Code, w.Body.String())
				}
				check(operation, w.Body.String(), true, true)
				check(operation, strings.Replace(w.Body.String(), `{`, `{"options":{},`, 1), true, false)
			}
			if combined {
				check("register-options", `{"mode":"signup","flowID":"AAAAAAAAAAAAAAAAAAAAAQ"}`, false, true)
			} else {
				check("register-options", `{"mode":"signup","flowID":"AAAAAAAAAAAAAAAAAAAAAQ"}`, false, false)
			}
		})
	}
}

func TestSessionEnrollmentPreservesOptionalEmptyLabelAndRejectsIncompleteConfiguration(t *testing.T) {
	c, _, _, _, _ := sessionEnrollmentFixture(t)
	for _, change := range []func(*SessionEnrollmentConfig){func(c *SessionEnrollmentConfig) { c.Service = nil }, func(c *SessionEnrollmentConfig) { c.Sessions = nil }, func(c *SessionEnrollmentConfig) { c.OptionsRate = nil }, func(c *SessionEnrollmentConfig) { c.VerificationRate = nil }, func(c *SessionEnrollmentConfig) { c.CSRFKeys = nil }, func(c *SessionEnrollmentConfig) { c.CSRFKeys = append(c.CSRFKeys, c.CSRFKeys[0]) }, func(c *SessionEnrollmentConfig) { c.Now = nil }, func(c *SessionEnrollmentConfig) { c.PolicyRevision = 0 }, func(c *SessionEnrollmentConfig) { c.Audience = "" }, func(c *SessionEnrollmentConfig) { c.MaximumDuration = 0 }} {
		bad := c
		change(&bad)
		if _, err := NewSessionEnrollmentOptionsHandler(bad); err == nil {
			t.Fatal("incomplete owner selected")
		}
		if _, err := NewSessionEnrollmentVerifyHandler(bad); err == nil {
			t.Fatal("incomplete completion owner selected")
		}
	}
	for _, label := range []string{"omitted", "empty"} {
		c, owner, _, cookie, csrf := sessionEnrollmentFixture(t)
		body := `{"mode":"session","phase":"assertion"}`
		if label == "empty" {
			body = `{"mode":"session","phase":"assertion","label":""}`
		}
		h, err := NewSessionEnrollmentOptionsHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, enrollmentRequest("register-options", body, cookie, csrf))
		if w.Code != 403 || owner.assertions != 1 || owner.request.Label != "" {
			t.Fatal("optional empty label changed", label)
		}
	}
}

func TestSessionEnrollmentDisabledProfilesExposeNoSessionVariant(t *testing.T) {
	legacy, old, _, cookie, device, csrf := registrationFixture(t)
	signup, signupOwner, _, _ := signupFixture(t)
	for _, selection := range []FeatureConfig{{Registration: &legacy}, {Signup: &signup}} {
		f, err := NewFeature(selection)
		if err != nil {
			t.Fatal(err)
		}
		h, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(document.JSON()), `"const":"session"`) || strings.Contains(string(document.JSON()), "session-assertion-options") {
			t.Fatal("disabled session enrollment advertised")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, registrationRequest("register-options", enrollmentAssertionWire, cookie, device, csrf))
		if w.Code != 400 || old.options != 0 || signupOwner.options != 0 {
			t.Fatal("unselected enrollment variant reached owner", w.Code)
		}
	}
}

func TestSessionEnrollmentHooksSeeOnlyDetachedPrincipalAndCannotReplaceCustody(t *testing.T) {
	c, owner, reader, cookie, csrf := sessionEnrollmentFixture(t)
	observed := false
	h, err := NewSessionEnrollmentOptionsHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{transportHook(identityhttp.MiddlewareAfterAuth, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		state, ok := identityhttp.PipelineValue[SessionEnrollmentState](r)
		tenant, user, authenticated := state.Principal()
		if !ok || !authenticated || tenant != "tenant-a" || user != "user-a" {
			t.Fatal("actual authenticated principal missing")
		}
		for _, value := range []any{state, struct{ private SessionEnrollmentState }{state}} {
			for _, format := range []string{"%v", "%+v", "%#v"} {
				wire := fmt.Sprintf(format, value)
				for _, forbidden := range []string{"user-a", "Additional key", "tenant.example"} {
					if strings.Contains(wire, forbidden) {
						t.Fatal("enclosing diagnostics leaked original custody")
					}
				}
			}
		}
		observed = true
		r.Header.Set("Cookie", "overridden=forbidden")
		r.Header.Set("X-CSRF-Token", "overridden")
		r.Header.Set("Idempotency-Key", "overridden")
		next.ServeHTTP(w, r)
	})})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, enrollmentRequest("register-options", enrollmentAssertionWire, cookie, csrf))
	if w.Code != 403 || !observed || reader.reads != 1 || owner.assertions != 1 || owner.request.Label != "Additional key" {
		t.Fatal("hook replaced/repeated authentication or original intent")
	}
	want, _ := identity.NewIdempotencyKey([]byte("original-register-options"))
	wantDigest, _ := want.Digest([32]byte{1})
	gotDigest, _ := owner.key.Digest([32]byte{1})
	if gotDigest != wantDigest {
		t.Fatal("hook replaced original key")
	}
}
