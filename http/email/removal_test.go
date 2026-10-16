package emailhttp_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
)

// These doubles prove transport custody, not native signature or SQL authority.
type removalOwner struct {
	*requestOwner
	removals, rates int
	last            email.AddressRemoveRequest
	invalid         bool
	foreign         bool
	administrative  bool
	substituteActor bool
}

func (s *removalOwner) AdministrativeRemovalConfigured() bool { return s.administrative }

func (s *removalOwner) AddressRemoveRateSource(ctx context.Context, r email.AddressRemoveRequest) (identity.UserID, error) {
	s.rates++
	if err := r.Validate(); err != nil {
		return "", err
	}
	return identity.UserID(r.Caller.Request.Subject.ID), ctx.Err()
}
func (s *removalOwner) AddressRemove(_ context.Context, r email.AddressRemoveRequest) (identity.CommandResult, error) {
	s.removals++
	s.last = r
	if s.invalid {
		return identity.CommandResult{}, nil
	}
	id, _ := identity.NewCommandID()
	op := identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.address-remove", SchemaID: "identity.email.address-remove.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b := identity.CommandBinding{CommandID: id, TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, RecordID: string(r.AddressID), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "email-removal", PolicyVersion: 9, CorrelationID: string(id)}
	if r.TargetSubjectID != "" {
		b.UserID = r.TargetSubjectID
	}
	if s.substituteActor {
		b.ActorID = identity.ActorID(b.UserID)
	}
	if s.foreign {
		b.TenantID = "foreign"
	}
	cascade, _ := identity.NewCascadeID()
	c := &identity.LifecycleCascadeAdmission{CascadeID: cascade, Generation: 1, Kind: identity.IdentifierRemovalCascade, TenantID: b.TenantID, UserID: b.UserID, IdentifierID: r.AddressID, AuthorityVersion: 2, ManifestVersion: "identity-lifecycle-consumers-v1", Status: identity.RevocationPending}
	for _, id := range identity.IdentifierRemovalConsumers() {
		c.Owners = append(c.Owners, identity.RevocationOwnerReceipt{Owner: id, Status: identity.RevocationPending})
	}
	return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "removal-audit", Feature: &identity.FeatureReceipt{Operation: op, BeforeVersion: r.ExpectedIdentifierVersion, AfterVersion: r.ExpectedIdentifierVersion + 1}, Cascade: c}, nil
}

func TestAdministrativeRemovalTransportKeepsStoredProofActorAndExactTarget(t *testing.T) {
	for _, mode := range []string{"selected", "disabled", "missing-native", "substituted-result"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, r := removalFixture(t)
			c.AdministrativeTargets = mode != "disabled"
			owner.administrative = mode != "missing-native"
			owner.substituteActor = mode == "substituted-result"
			body := `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","targetSubjectID":"other-user","addressID":"target-address","expectedIdentifierVersion":"1","expectedVerificationVersion":"1","reason":"user-requested","primaryDisposition":"leave-unassigned","recoveryDisposition":"preserve-verified-email"}`
			r.Body = io.NopCloser(strings.NewReader(body))
			r.ContentLength = int64(len(body))
			h, err := emailhttp.NewAddressRemoveHandler(c)
			if mode == "missing-native" {
				if err == nil || h != nil {
					t.Fatal("missing administrative owner admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 200
			if mode == "disabled" {
				want = 400
			}
			if mode == "substituted-result" {
				want = 503
			}
			if w.Code != want || len(w.Result().Cookies()) != 0 {
				t.Fatal("administrative transport boundary", mode, w.Code)
			}
			if mode == "disabled" {
				if owner.removals != 0 || owner.rates != 0 || owner.reads != 0 {
					t.Fatal("disabled targeting reached authority")
				}
				return
			}
			if owner.last.TargetSubjectID != "other-user" || owner.last.Caller.Request.Resource.ID != "other-user" || string(owner.last.Caller.Request.Subject.ID) != owner.proof.Proof.Subject || owner.last.Caller.Request.Subject.ID == "other-user" {
				t.Fatal("target replaced stored proof actor")
			}
		})
	}
}
func (s *removalOwner) AddressRemoveRecover(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (identity.CommandResult, error) {
	return identity.CommandResult{}, identity.ForbiddenError{}
}

func removalFixture(t *testing.T) (emailhttp.RemovalConfig, *removalOwner, *http.Request) {
	t.Helper()
	base, source, r := emailRequestFixture(t, true)
	source.proof.Action = "identity.email.address-remove"
	owner := &removalOwner{requestOwner: source}
	r.URL.Path = "/v1/email/address-remove"
	r.RequestURI = r.URL.Path
	body := `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","addressID":"target-address","expectedIdentifierVersion":"1","expectedVerificationVersion":"1","reason":"user-requested","primaryDisposition":"leave-unassigned","recoveryDisposition":"preserve-verified-email"}`
	r.Body = io.NopCloser(strings.NewReader(body))
	r.ContentLength = int64(len(body))
	return emailhttp.RemovalConfig{Network: base.Network, Proofs: owner, Service: owner, Rate: base.SecretRate, Cookie: base.Cookie, Origin: base.Origin, PolicyRevision: 9, MaximumDuration: base.MaximumDuration}, owner, r
}

func TestEmailRemovalHTTPClosedInput(t *testing.T) {
	for _, mode := range []string{"origin", "csrf", "key", "bearer", "query", "duplicate", "override", "version", "null", "disposition", "method"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, r := removalFixture(t)
			switch mode {
			case "origin":
				r.Header.Set("Origin", "https://foreign.example")
			case "csrf":
				r.Header.Del("X-CSRF-Token")
			case "key":
				r.Header.Del("Idempotency-Key")
			case "bearer":
				r.Header.Set("Authorization", "Bearer invalid")
			case "query":
				r.URL.RawQuery = "tenantID=foreign"
			case "method":
				r.Method = http.MethodDelete
			default:
				wire, _ := io.ReadAll(r.Body)
				body := string(wire)
				switch mode {
				case "duplicate":
					body = strings.TrimSuffix(body, "}") + `,"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"}`
				case "override":
					body = strings.TrimSuffix(body, "}") + `,"tenantID":"foreign"}`
				case "version":
					body = strings.Replace(body, `"expectedIdentifierVersion":"1"`, `"expectedIdentifierVersion":"01"`, 1)
				case "null":
					body = strings.Replace(body, `"reason":"user-requested"`, `"reason":null`, 1)
				case "disposition":
					body = strings.Replace(body, "leave-unassigned", "choose-first", 1)
				}
				r.Body = io.NopCloser(strings.NewReader(body))
				r.ContentLength = int64(len(body))
			}
			h, err := emailhttp.NewAddressRemoveHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || owner.removals != 0 || owner.rates != 0 || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("invalid removal reached native authority", w.Code)
			}
		})
	}
}

func TestEmailRemovalHTTPPendingCascadeNoCredentials(t *testing.T) {
	c, owner, r := removalFixture(t)
	h, err := emailhttp.NewAddressRemoveHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out emailhttp.RemovalResponse
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Code != 200 || !out.Removed || out.CommitOutcome != "committed" || out.CascadeID == "" || out.CascadeStatus != "pending" || out.CascadeGeneration != 1 || owner.removals != 1 || owner.rates != 1 || owner.last.Validate() != nil || len(w.Result().Cookies()) != 0 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("removal lost original response custody", w.Code)
	}
}

func TestEmailRemovalHTTPExplicitReplacement(t *testing.T) {
	for _, mode := range []string{"selected", "missing-id", "missing-version", "unknown", "old-disposition", "noncanonical", "self"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, r := removalFixture(t)
			wire, _ := io.ReadAll(r.Body)
			var body map[string]string
			_ = json.Unmarshal(wire, &body)
			body["primaryDisposition"] = "replace-primary"
			body["replacementAddressID"] = "remaining-address"
			body["expectedReplacementIdentifierVersion"] = "5"
			body["expectedReplacementVerificationVersion"] = "7"
			switch mode {
			case "missing-id":
				delete(body, "replacementAddressID")
			case "missing-version":
				delete(body, "expectedReplacementVerificationVersion")
			case "unknown":
				body["override"] = "foreign"
			case "old-disposition":
				body["primaryDisposition"] = "leave-unassigned"
			case "noncanonical":
				body["expectedReplacementIdentifierVersion"] = "05"
			case "self":
				body["replacementAddressID"] = "target-address"
			}
			wire, _ = json.Marshal(body)
			r.Body = io.NopCloser(strings.NewReader(string(wire)))
			r.ContentLength = int64(len(wire))
			h, err := emailhttp.NewAddressRemoveHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if mode == "selected" {
				if w.Code != 200 || owner.removals != 1 || owner.last.PrimaryDisposition != email.ReplacePrimaryWithVerifiedEmail || owner.last.ReplacementPrimary.ID != "remaining-address" || owner.last.ReplacementPrimary.ExpectedIdentifierVersion != 5 || owner.last.ReplacementPrimary.ExpectedVerificationVersion != 7 {
					t.Fatal("explicit replacement did not reach selected native removal", w.Code)
				}
			} else if w.Code < 400 || owner.removals != 0 || owner.rates != 0 {
				t.Fatal("invalid replacement reached owner", w.Code)
			}
		})
	}
}

func TestEmailRemovalHTTPRejectsForeignOutcomeWithoutCorrelation(t *testing.T) {
	c, owner, r := removalFixture(t)
	owner.foreign = true
	h, err := emailhttp.NewAddressRemoveHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out emailhttp.RemovalResponse
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Code != 503 || out.Removed || out.CommandID != "" || out.CascadeID != "" || out.CommitOutcome != "unknown" || owner.removals != 1 {
		t.Fatal("foreign outcome disclosed correlation or claimed commit", w.Code)
	}
}

func TestEmailRemovalSelectedFeatureDocumentsHandler(t *testing.T) {
	for _, selected := range []bool{false, true} {
		t.Run(strconv.FormatBool(selected), func(t *testing.T) {
			c, owner, r := removalFixture(t)
			c.AdministrativeTargets, owner.administrative = selected, selected
			f, err := emailhttp.NewFeature(emailhttp.FeatureConfig{AddressRemove: &c})
			if err != nil {
				t.Fatal(err)
			}
			h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Email removal", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(doc.JSON()), "/v1/email/address-remove") || strings.Contains(string(doc.JSON()), "/v1/email/change-request") {
				t.Fatal("selection advertises incorrect routes")
			}
			if strings.Contains(string(doc.JSON()), "targetSubjectID") != selected {
				t.Fatal("administrative selector metadata differs from selected handler")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 200 || owner.removals != 1 {
				t.Fatal("documented removal route not usable", w.Code)
			}
		})
	}
}
