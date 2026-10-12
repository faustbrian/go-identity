package magiclinkpostgres

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/magiclink"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestOriginalFlowDigestIncludesRememberPolicy(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	makeFlow := func(choice session.RememberChoice) session.PreAuthTransaction {
		remember, err := session.ResolveRememberPolicy(choice, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: identity.PreAuthTransactionID(id), Intent: session.PreAuthIntent{TenantID: "tenant", Action: "identity.magic-link.consume", Origin: "https://app.test", CallbackURL: "https://app.test/login", Nonce: [32]byte{1}, Remember: remember, PolicyID: "policy", PolicyVersion: 1}, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, Cookie: session.TokenDigest{KeyVersion: 1, Sum: [32]byte{1}}, Version: 1})
		if err != nil {
			t.Fatal(err)
		}
		return flow
	}
	first := makeFlow(session.BrowserSession)
	second := makeFlow(session.PersistentSession)
	f, _ := first.Bindings()
	s, _ := second.Bindings()
	s.Binding.ID = f.Binding.ID
	second, err := session.NewPreAuthTransaction(s)
	if err != nil {
		t.Fatal(err)
	}
	p := &requestPhase{service: &RequestService{config: func() RequestConfig { return RequestConfig{IntentKey: [32]byte{2}} }}, flow: first}
	one, err := p.flowDigest()
	if err != nil {
		t.Fatal(err)
	}
	p.flow = second
	two, err := p.flowDigest()
	if err != nil {
		t.Fatal(err)
	}
	if one == two {
		t.Fatal("original-flow binding omitted remember choice/lifetimes")
	}
	p.flow = first
	again, err := p.flowDigest()
	if err != nil || again != one {
		t.Fatal("unchanged original flow changed its binding")
	}
}

func signedRequestScopeFixture(t *testing.T) (*requestPhase, requestSelection) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	id, _ := identity.NewCommandID()
	user, _ := identity.NewSubjectID()
	identifier, _ := identity.NewSubjectID()
	remember, _ := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
	flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: identity.PreAuthTransactionID(id), Intent: session.PreAuthIntent{TenantID: "tenant", Action: "identity.magic-link.consume", Origin: "https://app.test", CallbackURL: "https://app.test/login", Nonce: [32]byte{1}, Remember: remember, PolicyID: "policy", PolicyVersion: 1}, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, Cookie: session.TokenDigest{KeyVersion: 1, Sum: [32]byte{1}}, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	op := requestOperation()
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: identity.CommandBinding{CommandID: id, TenantID: "tenant", AnonymousFlowID: string(id), ActorID: "ingress", ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "policy", PolicyVersion: 1, CorrelationID: string(id)}, Operation: op})
	if err != nil {
		t.Fatal(err)
	}
	config := RequestConfig{IntentKey: [32]byte{2}, IssuerURL: "https://issuer.test", Lifetime: time.Minute, Issuer: issuerpg.IssuerConfig{Audience: "identity"}}
	p := &requestPhase{original: command, service: &RequestService{configuration: [32]byte{3}, config: func() RequestConfig { return config }}, flow: flow, request: magiclink.RequestRequest{Intent: magiclink.SignInOnly, Callback: "https://app.test/login"}}
	r := kernel.RecipientRecord{Query: kernel.RecipientQuery{TenantID: "tenant", Kind: identity.IdentifierEmail, CanonicalValue: "user@example.test", Eligibility: kernel.RecipientVerified}, User: identity.User{ID: identity.UserID(user), TenantID: "tenant", Status: identity.StatusActive, Version: 1}, Identifier: identity.Identifier{ID: identity.IdentifierID(identifier), UserID: identity.UserID(user), Kind: identity.IdentifierEmail, CanonicalValue: "user@example.test", Verified: true, Version: 2}, Verification: identity.Verification{IdentifierID: identity.IdentifierID(identifier), State: identity.VerificationVerified, VerifiedAt: now, Version: 3}, UserAuthorityVersion: 4, IdentifierAuthorityVersion: 5, CredentialAuthorityVersion: 6, ObservedAt: now}
	s := requestSelection{recipient: r, factor: 7, issued: now, expires: now.Add(time.Minute)}
	return p, s
}

func TestSignedRequestPayloadRetainsOriginalAuthority(t *testing.T) {
	p, s := signedRequestScopeFixture(t)
	spec, _ := p.original.Feature()
	id, user, r, now := spec.Binding.CommandID, s.recipient.User.ID, s.recipient, s.issued
	payload, err := p.payload(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.Caveats["magiclink.supersession"]) != 64 {
		t.Fatal("issued payload lacks exact original-flow supersession scope")
	}
	if payload.Subject != string(user) || payload.MaxUses != 1 || payload.Caveats["magiclink.factor-version"] != "7" || payload.CorrelationID != string(id) || payload.Caveats["magiclink.flow"] != string(id) || payload.ExpiresAt != s.expires {
		t.Fatal("original recipient/flow/factor timeline lost")
	}
	signer, _ := capability.NewHMACSHA256Signer("test", []byte(strings.Repeat("x", 32)))
	verifier, _ := capability.NewHMACSHA256Verifier([]byte(strings.Repeat("x", 32)))
	keys, _ := capability.NewKeySet([]capability.Key{{ID: "test", Verifier: verifier}})
	payload.ID = string(id)
	token, err := capability.Issue(context.Background(), payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(token)+len("https://app.test/magic#token=") > 2048 {
		t.Fatalf("ordinary signed profile cannot fit the delivery URL: %d bytes", len(token))
	}
	grant, err := capability.Verify(context.Background(), token, keys, capability.VerifyOptions{Now: now, Limits: capability.DefaultLimits()})
	if err != nil || grant.Payload().Caveats["magiclink.canonical-email"] != r.Identifier.CanonicalValue {
		t.Fatal("signed primary-recipient profile cannot be verified", err)
	}
	bad := s
	bad.expires = now.Add(2 * time.Minute)
	if _, err := p.payload(bad); err == nil {
		t.Fatal("grant outlived original browser flow")
	}
	bad = s
	bad.factor = 0
	if _, err := p.payload(bad); err == nil {
		t.Fatal("missing factor authority issued profile")
	}
}

func TestProspectiveSignupPayloadDoesNotInventCurrentRecipientAuthority(t *testing.T) {
	p, s := signedRequestScopeFixture(t)
	spec, _ := p.original.Feature()
	b := spec.Binding
	b.AnonymousFlowID, b.OperationID, b.UserID = "", "identity.user.create", s.recipient.User.ID
	b.SchemaID, b.SchemaVersion = "signup-fields", 1
	i := s.recipient.Identifier
	i.Version, i.Verified, i.Primary = 1, false, false
	creation := kernel.MagicLinkRegistrationIntent{Creation: identity.CreateUserCommand{Binding: b, Status: identity.StatusActive}, Identifier: i, ComparisonProfile: "email-v1", EmailPossessionPolicyVersion: 9}
	s.prospective = &creation
	s.recipient = kernel.RecipientRecord{Query: s.recipient.Query, Suppressed: true}
	s.factor = 0
	p.request.Intent = magiclink.SignupIfAllowed
	payload, err := p.payload(s)
	if err != nil {
		t.Fatal("prospective signup profile unavailable", err)
	}
	digest, _ := kernel.MagicLinkRegistrationDigest(creation)
	if payload.Subject != string(b.UserID) || payload.Caveats["magiclink.prospective"] != "1" || payload.Caveats["magiclink.creation-digest"] != fmt.Sprintf("%x", digest) || payload.Caveats["magiclink.email-policy-version"] != "9" || payload.Caveats["magiclink.intent"] != "signup-if-allowed" {
		t.Fatal("prospective creation intent lost")
	}
	for _, name := range []string{"identifier-version", "verification-version", "user-authority-version", "identifier-authority-version", "credential-authority-version", "factor-version"} {
		if payload.Caveats["magiclink."+name] != "1" {
			t.Fatal("prospective profile borrowed existing recipient authority")
		}
	}
	if payload.ExpiresAt != s.expires || payload.IssuedAt != s.issued || payload.Caveats["magiclink.canonical-email"] != i.CanonicalValue {
		t.Fatal("prospective profile changed original address or timeline")
	}
	if _, err := issuerpg.MagicLinkScopeFromPayload(payload); err != nil {
		t.Fatal("prospective profile incompatible with actual issuer", err)
	}
	payload.ID = string(spec.Binding.CommandID)
	limits := capability.DefaultLimits()
	limits.MaxCaveats = 18 // Explicit selected signup profile, not global defaults.
	grant := signConsumptionScope(t, payload, s.issued, limits)
	signer, _ := capability.NewHMACSHA256Signer("test", []byte(strings.Repeat("x", 32)))
	wire, err := capability.Issue(context.Background(), payload, signer, limits)
	if err != nil || len(wire)+len("https://app.test/magic#token=") > 2048 {
		t.Fatalf("prospective profile cannot fit selected delivery URL: %d bytes, %v", len(wire), err)
	}
	if grant.Payload().Caveats["magiclink.creation-digest"] != payload.Caveats["magiclink.creation-digest"] {
		t.Fatal("actual signer lost prospective creation binding")
	}
	for name, change := range map[string]func(*requestSelection){
		"verified flag":       func(s *requestSelection) { s.prospective.Identifier.Verified = true },
		"existing recipient":  func(s *requestSelection) { s.recipient = signedRecipient(t) },
		"current factor":      func(s *requestSelection) { s.factor = 1 },
		"foreign binding":     func(s *requestSelection) { s.prospective.Creation.Binding.TenantID = "foreign" },
		"foreign discovery":   func(s *requestSelection) { s.recipient.Query.TenantID = "foreign" },
		"different mailbox":   func(s *requestSelection) { s.prospective.Identifier.CanonicalValue = "foreign@example.test" },
		"missing policy":      func(s *requestSelection) { s.prospective.EmailPossessionPolicyVersion = 0 },
		"missing prospective": func(s *requestSelection) { s.prospective = nil },
		"different flow":      func(s *requestSelection) { s.prospective.Creation.Binding.CommandID, _ = identity.NewCommandID() },
	} {
		t.Run(name, func(t *testing.T) {
			bad := s
			copy := creation
			bad.prospective = &copy
			change(&bad)
			if _, err := p.payload(bad); err == nil {
				t.Fatal("invalid prospective creation signed")
			}
		})
	}
	p.request.Intent = magiclink.SignInOnly
	if _, err := p.payload(s); err == nil {
		t.Fatal("signin-only borrowed signup authority")
	}
}

func signedRecipient(t *testing.T) kernel.RecipientRecord {
	t.Helper()
	_, s := signedRequestScopeFixture(t)
	return s.recipient
}
