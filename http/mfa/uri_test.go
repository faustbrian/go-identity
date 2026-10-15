package mfahttp

import (
	"context"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestURIHTTPRequiresOriginalNativeCustody(t *testing.T) {
	if h, err := NewURIHandler(URIConfig{}); err == nil || h != nil {
		t.Fatal("unconfigured HTTP acquired disclosure authority")
	}
}

func TestURIHTTPFeatureSelectsOnlyRealDisclosure(t *testing.T) {
	c, o, _, _, r := uriFixture(t)
	f, err := NewFeature(FeatureConfig{URI: &c})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil || len(ops) != 1 || ops[0].Record.OperationID != "identity.mfa.totp-uri" {
		t.Fatal("URI selected missing/unrelated operation", err)
	}
	w := httptest.NewRecorder()
	ops[0].Handler.ServeHTTP(w, r)
	if w.Code != 200 || o.calls != 1 {
		t.Fatal("selected URI descriptor did not reveal", w.Code)
	}
}

type uriOwner struct {
	reads, calls             int
	until                    time.Time
	sourceErr, errorResult   error
	result                   mfa.TotpUriResult
	last                     mfa.TotpUriRequest
	afterSource, afterReveal func()
}

func (o *uriOwner) TotpUriRateSource(ctx context.Context, r mfa.TotpUriRequest) (time.Duration, time.Time, error) {
	o.reads++
	o.last = r
	if _, ok := ctx.Deadline(); !ok || r.Validate() != nil {
		panic("unbounded or invalid source custody")
	}
	if o.afterSource != nil {
		o.afterSource()
	}
	return time.Minute, o.until, o.sourceErr
}
func (o *uriOwner) TotpUri(ctx context.Context, r mfa.TotpUriRequest) (mfa.TotpUriResult, error) {
	o.calls++
	o.last = r
	if _, ok := ctx.Deadline(); !ok || r.Validate() != nil {
		panic("unbounded or invalid reveal")
	}
	if o.afterReveal != nil {
		o.afterReveal()
	}
	return o.result, o.errorResult
}
func (*uriOwner) RecoverTotpUri(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (mfa.TotpUriResult, error) {
	return mfa.TotpUriResult{}, identity.UnavailableError{}
}

func uriFixture(t *testing.T) (URIConfig, *uriOwner, *enableReader, *enableClock, *http.Request) {
	t.Helper()
	c, _, reader, clock, r := enableFixture(t)
	command, _ := identity.NewCommandID()
	enrollment, _ := identity.NewCommandID()
	r.URL.Path = "/v1/mfa/totp-uri"
	r.RequestURI = r.URL.RequestURI()
	r.Header.Del("Idempotency-Key")
	body := `{"commandID":"` + string(command) + `","enrollmentID":"` + string(enrollment) + `"}`
	r.Body = ioBody(body)
	r.ContentLength = int64(len(body))
	o := &uriOwner{until: clock.now.Add(10 * time.Second), result: mfa.TotpUriResult{Outcome: identity.CommitOutcomeCommitted, URI: mfa.RevealOnceURI{EnrollmentID: mfa.EnrollmentID(enrollment), URI: "otpauth://totp/synthetic?secret=SYNTHETIC"}}}
	return URIConfig{Network: c.Network, Sessions: c.Sessions, Service: o, Rate: c.Rate, Cookie: c.Cookie, TrustedOrigins: c.TrustedOrigins, PolicyRevision: c.PolicyRevision, Now: c.Now, MaximumDuration: c.MaximumDuration}, o, reader, clock, r
}

func TestURIHTTPConservesOriginalCustodyAndDeadline(t *testing.T) {
	for _, mode := range []string{"fresh", "replay", "source-denied", "unknown", "error", "source-expired", "delivery-expired", "foreign-result"} {
		t.Run(mode, func(t *testing.T) {
			c, o, _, clock, r := uriFixture(t)
			switch mode {
			case "replay":
				o.result.URI = mfa.RevealOnceURI{}
			case "source-denied":
				o.sourceErr = identity.ForbiddenError{}
			case "unknown":
				o.result.Outcome = identity.CommitOutcomeUnknown
			case "error":
				o.errorResult = identity.ForbiddenError{}
			case "source-expired":
				o.afterSource = func() { clock.now = o.until }
			case "delivery-expired":
				o.afterReveal = func() { clock.now = o.until }
			case "foreign-result":
				o.result.URI.EnrollmentID = "foreign"
			}
			h, err := NewURIHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			w.Header().Set("Set-Cookie", "injected")
			w.Header().Set("Location", "injected")
			h.ServeHTTP(w, r)
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("Location") != "" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
				t.Fatal("URI output protection escaped")
			}
			if mode == "fresh" {
				if w.Code != 200 || o.reads != 1 || o.calls != 1 || o.last.Validate() != nil || !strings.Contains(w.Body.String(), "SYNTHETIC") {
					t.Fatal("original native URI custody not delivered", w.Code)
				}
			} else if w.Code == 200 || strings.Contains(w.Body.String(), "SYNTHETIC") {
				t.Fatal("non-deliverable result revealed provisioning material")
			}
			if (mode == "source-denied" || mode == "source-expired") && o.calls != 0 {
				t.Fatal("inadmissible source reached reveal")
			}
		})
	}
}

func TestURIHTTPRejectsAlternativeCustodyBeforeOwners(t *testing.T) {
	for _, mode := range []string{"key", "authorization", "csrf", "origin", "subject", "duplicate", "missing-cookie", "query"} {
		t.Run(mode, func(t *testing.T) {
			c, o, reader, _, r := uriFixture(t)
			switch mode {
			case "key":
				r.Header.Set("Idempotency-Key", "forbidden")
			case "authorization":
				r.Header.Set("Authorization", "Bearer forbidden")
			case "csrf":
				r.Header.Del("X-CSRF-Token")
			case "origin":
				r.Header.Set("Origin", "https://foreign.example")
			case "subject":
				r.Body = ioBody(`{"commandID":"ignored","enrollmentID":"ignored","userID":"foreign"}`)
			case "duplicate":
				r.Body = ioBody(`{"commandID":"ignored","commandID":"ignored","enrollmentID":"ignored"}`)
			case "missing-cookie":
				r.Header.Del("Cookie")
			case "query":
				r.URL.RawQuery = "x=1"
			}
			h, err := NewURIHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code == 200 || reader.calls != 0 || o.reads != 0 || o.calls != 0 {
				t.Fatal("alternate custody reached native owner", mode, w.Code)
			}
		})
	}
}
