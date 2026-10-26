package organizationhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

type ownerTransferPort struct {
	request     organization.OwnerTransferOperationRequest
	calls       int
	result      organization.StoreResult
	proof       auth.ReauthenticationProof
	native      *nativePort
	lookups     int
	proofID     auth.ProofID
	proofErr    error
	beforeProof func()
	change      func(*organization.StoreResult)
}

func (p *ownerTransferPort) OwnerTransfer(ctx context.Context, r organization.OwnerTransferOperationRequest, network string) (organization.StoreResult, error) {
	p.request = r
	p.calls++
	p.native.network = network
	out, err := p.native.mutation(ctx, organization.OwnerTransfer, r.Authentication, r.OrganizationID, r.TargetUserID)
	if out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		out.Receipt.Feature.BeforeVersion = r.OrganizationVersion
		out.Receipt.Feature.AfterVersion = r.OrganizationVersion + 1
	}
	if p.change != nil {
		p.change(&out)
	}
	return out, err
}
func (p *ownerTransferPort) Reauthentication(ctx context.Context, id auth.ProofID) (auth.SignedReauthenticationRecord, error) {
	p.lookups++
	p.proofID = id
	if p.beforeProof != nil {
		p.beforeProof()
	}
	return auth.SignedReauthenticationRecord{Proof: p.proof}, p.proofErr
}
func TestOwnerTransferIndependentSelection(t *testing.T) {
	f := newFixture(t)
	p := &ownerTransferPort{}
	f.c.Service, f.c.SafeRate, f.c.Invitations = nil, nil, nil
	f.c.OwnerTransferer = p
	f.c.OwnerTransferProofs = p
	f.c.OwnerTransferAudience = "organization-action"
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, OwnerTransfer: true})
	if err != nil {
		t.Fatal("independent transfer selection", err)
	}
	_, err = identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
}

const transferBody = `{"organizationID":"organization-a","targetUserID":"other-user","organizationVersion":7,"sourceVersion":2,"targetVersion":3,"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"}`

// This port fixture proves transport custody, not proof provenance or native
// owner authority. Genuine password/native PostgreSQL composition is separate.
func transferFixture(t testing.TB) (*fixture, *ownerTransferPort, http.Handler) {
	t.Helper()
	f := newFixture(t)
	p := &ownerTransferPort{native: f.port, proof: auth.ReauthenticationProof{Proof: auth.Proof{ID: "AAAAAAAAAAAAAAAAAAAAAQ", Tenant: "tenant-a", Subject: "user-a", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "identity.password.verify", Audience: "organization-action", IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Minute)}, SessionID: "session-a", SessionVersion: 1, Action: string(organization.OwnerTransfer)}}
	f.c.Service, f.c.SafeRate, f.c.Invitations = nil, nil, nil
	f.c.OwnerTransferer, f.c.OwnerTransferProofs, f.c.OwnerTransferAudience = p, p, "organization-action"
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, OwnerTransfer: true})
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return f, p, h
}
func transferRequest(f *fixture, body string) *http.Request {
	return request(f, "/v1/organization/owner-transfer", body, true)
}
func TestOwnerTransferCarriesOriginalProofAndKeyWithoutRenewal(t *testing.T) {
	f, p, h := transferFixture(t)
	// Retained original projection belongs to an earlier session and is expired;
	// native original-key recovery, not HTTP, decides whether it is history.
	p.proof.SessionID = "historical-session"
	p.proof.Proof.IssuedAt = f.now.Add(-2 * time.Minute)
	p.proof.Proof.ExpiresAt = f.now.Add(-time.Minute)
	w := serve(t, h, transferRequest(f, transferBody))
	var out organizationhttp.MutationResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.MemberID != "other-user" || out.BeforeVersion != 7 || out.AfterVersion != 8 || out.Recovery == nil {
		t.Fatal("original transfer receipt lost", w.Code)
	}
	if p.calls != 1 || p.lookups != 1 || p.proofID != p.proof.Proof.ID || p.request.Proof != p.proof || p.request.OrganizationVersion != 7 || p.request.SourceVersion != 2 || p.request.TargetVersion != 3 || p.request.TargetUserID != "other-user" || p.request.Authentication.Bearer.Token() != f.wire || p.native.network != "198.51.100.7" || f.rate.calls != 1 {
		t.Fatal("transfer intent, proof, rate or native custody changed")
	}
	key, _ := identity.NewIdempotencyKey([]byte("original-key"))
	a, _ := key.Digest([32]byte{1})
	b, _ := p.request.IdempotencyKey.Digest([32]byte{1})
	if a != b {
		t.Fatal("initiating key changed")
	}
	for _, private := range []string{f.wire, string(p.proof.Proof.ID), "historical-session", "proofID", "password"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("transfer proof or credential escaped")
		}
	}
}
func TestOwnerTransferRejectsClosedInputBeforeOwnerReads(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"missing-key":      func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"duplicate-key":    func(r *http.Request) { r.Header.Add("Idempotency-Key", "second") },
		"duplicate-bearer": func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) },
		"cookie-only": func(r *http.Request) {
			r.Header.Del("Authorization")
			r.AddCookie(&http.Cookie{Name: "__Host-session", Value: fakedCookie})
		},
		"query":  func(r *http.Request) { r.URL.RawQuery = "actorID=other" },
		"method": func(r *http.Request) { r.Method = http.MethodPut },
	} {
		t.Run(name, func(t *testing.T) {
			f, p, h := transferFixture(t)
			r := transferRequest(f, transferBody)
			change(r)
			w := serve(t, h, r)
			want := 400
			if name == "method" {
				want = 405
			}
			if w.Code != want || p.calls != 0 || p.lookups != 0 || f.reads.Load() != 0 {
				t.Fatal("alternate input reached authority", w.Code)
			}
		})
	}
	for _, body := range []string{`{}`, strings.Replace(transferBody, `"sourceVersion":2`, `"sourceVersion":0`, 1), strings.Replace(transferBody, `"targetVersion":3`, `"targetVersion":18446744073709551615`, 1), strings.Replace(transferBody, `"organizationVersion":7`, `"organizationVersion":7e0`, 1), strings.Replace(transferBody, `"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"`, `"proofID":"short"`, 1), strings.Replace(transferBody, `"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"`, `"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","commandID":"override"`, 1), strings.Replace(transferBody, `"targetUserID":"other-user"`, `"targetUserID":"other-user","targetUserID":"second"`, 1), strings.Replace(transferBody, `"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"`, `"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","proof":{"sessionID":"override"}`, 1)} {
		t.Run(body, func(t *testing.T) {
			f, p, h := transferFixture(t)
			w := serve(t, h, transferRequest(f, body))
			if w.Code != 400 || p.lookups != 0 || p.calls != 0 || f.reads.Load() != 0 {
				t.Fatal("malformed transfer reached authority", w.Code)
			}
		})
	}
}

const fakedCookie = "ambient-cookie-is-not-authority"

func TestOwnerTransferProofAndCurrentSessionFences(t *testing.T) {
	for _, mode := range []string{"unknown", "unavailable", "foreign-tenant", "foreign-user", "wrong-id", "wrong-action", "wrong-audience", "wrong-method", "inactive", "rate", "closed", "source-expired", "source-cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f, p, h := transferFixture(t)
			r := transferRequest(f, transferBody)
			want := 403
			switch mode {
			case "unknown":
				p.proofErr = auth.ErrInvalidProof
			case "unavailable":
				p.proofErr = errors.New("private source diagnostic")
				want = 503
			case "foreign-tenant":
				p.proof.Proof.Tenant = "other"
			case "foreign-user":
				p.proof.Proof.Subject = "other"
			case "wrong-id":
				p.proof.Proof.ID = "BBBBBBBBBBBBBBBBBBBBBB"
			case "wrong-action":
				p.proof.Action = string(organization.Update)
			case "wrong-audience":
				p.proof.Proof.Audience = "other"
			case "wrong-method":
				p.proof.Proof.Method = "passkey"
			case "inactive":
				f.inactive = true
			case "rate":
				f.rate.mode = 1
				want = 429
			case "closed":
				f.c.AdminRate.Close()
				want = 503
			case "source-expired":
				p.beforeProof = func() { f.now = f.now.Add(20 * time.Second) }
				want = 503
			case "source-cancelled":
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				r = r.WithContext(ctx)
				p.beforeProof = cancel
				want = 503
			}
			w := serve(t, h, r)
			if w.Code != want || p.calls != 0 || strings.Contains(w.Body.String(), "private") {
				t.Fatal("proof/current admission fence", mode, w.Code)
			}
			if (mode == "inactive" || mode == "rate" || mode == "closed") && p.lookups != 0 {
				t.Fatal("denied admission read proof")
			}
		})
	}
}
func TestOwnerTransferReceiptScopeEpochAndLateCommit(t *testing.T) {
	for _, mode := range []string{"foreign-actor", "foreign-target", "wrong-epoch", "unknown", "cancelled", "expired"} {
		t.Run(mode, func(t *testing.T) {
			f, p, h := transferFixture(t)
			r := transferRequest(f, transferBody)
			switch mode {
			case "foreign-actor":
				p.change = func(out *organization.StoreResult) { out.Receipt.Binding.ActorID = "other" }
			case "foreign-target":
				p.change = func(out *organization.StoreResult) { out.MemberID = "other"; out.Receipt.Binding.UserID = "other" }
			case "wrong-epoch":
				p.change = func(out *organization.StoreResult) {
					out.Receipt.Feature.BeforeVersion = 8
					out.Receipt.Feature.AfterVersion = 9
				}
			case "unknown":
				f.port.outcome = identity.CommitOutcomeUnknown
			case "cancelled":
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				r = r.WithContext(ctx)
				f.port.beforeCall = cancel
			case "expired":
				f.port.beforeCall = func() { f.now = f.now.Add(20 * time.Second) }
			}
			w := serve(t, h, r)
			var out organizationhttp.MutationResponse
			if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
				t.Fatal("unsafe or late response", w.Code)
			}
			if mode == "foreign-actor" || mode == "foreign-target" || mode == "wrong-epoch" {
				if out.CommandID != "" || out.Recovery != nil || out.Committed {
					t.Fatal("foreign original metadata leaked")
				}
			} else if mode == "unknown" {
				if out.Recovery == nil || out.CommitOutcome != "unknown" || out.Committed {
					t.Fatal("unknown original scope lost")
				}
			} else if !out.Committed || out.CommitOutcome != "committed" || out.Recovery == nil || out.BeforeVersion != 7 || out.AfterVersion != 8 {
				t.Fatal("late failure erased known commit")
			}
		})
	}
}
func TestOwnerTransferDisabledAndWire(t *testing.T) {
	f, _, _ := transferFixture(t)
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, OwnerTransfer: true})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Transfer", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	r := transferRequest(f, transferBody)
	w := serve(t, h, r)
	assertWireResponse(t, doc.JSON(), r, w)
	if len(doc.Operations()) != 1 || !strings.Contains(string(doc.JSON()), `"proofID"`) {
		t.Fatal("transfer schema missing")
	}
	f.c.Service = f.port
	feature, err = organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, MemberAdd: true})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err = identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "No transfer", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(doc.JSON()), `/v1/organization/owner-transfer`) || serve(t, h, r).Code != 404 {
		t.Fatal("disabled transfer exposed")
	}
}
func FuzzOwnerTransferClosedRequest(f *testing.F) {
	for _, seed := range []string{transferBody, `{}`, `null`, strings.Replace(transferBody, `"sourceVersion":2`, `"sourceVersion":0`, 1), strings.Replace(transferBody, `"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"`, `"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","proofID":"other"`, 1)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 4096 {
			return
		}
		x, p, h := transferFixture(t)
		w := serve(t, h, transferRequest(x, body))
		if p.calls != 0 && (p.calls != 1 || p.lookups != 1 || p.request.Validate() != nil || p.request.Authentication.Bearer.Token() != x.wire) {
			t.Fatal("unbounded or forged request reached native owner")
		}
		if w.Code == 200 && p.calls != 1 {
			t.Fatal("success bypassed native owner")
		}
	})
}
