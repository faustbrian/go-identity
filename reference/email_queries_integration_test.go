//go:build integration

package reference_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferencePostgresEmailQueries(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailAddressQueries: true})
}

func TestReferencePostgresEmailQueriesGraph(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailAddressQueries: true, emailChangeCase: "queries-graph"})
}

func referenceEmailQueryConfiguration() *reference.EmailAddressConfiguration {
	return &reference.EmailAddressConfiguration{Redact: func(_ context.Context, input identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
		return identity.RedactionPolicyDecision{VisibleFields: input.Fields, PolicyID: "email-read", PolicyVersion: 9, Reason: "owned-address"}, nil
	}, Native: identity.UserQueryConfig{MaximumDuration: 2 * time.Second, PolicyID: "email-read", PolicyVersion: 9, RedactionReasons: []identity.PolicyReason{"owned-address"}, ValidateCanonicalUserID: func(_ context.Context, id identity.UserID) error {
		_, err := identity.ParseSubjectID(string(id))
		return err
	}}}
}

type emailQueryConsumer interface {
	AddressList(context.Context, email.AddressListRequest) (email.AddressListResult, error)
	AddressGet(context.Context, email.AddressGetRequest) (email.AddressGetResult, error)
}

// The unchanged consumer graph registers, delivers, confirms and signs in first.
// No user/identifier/session rows are fabricated. This exercises the public
// query API over the actual kernel repository, not email HTTP or mutation.
func proveReferenceEmailQueries(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, cookies []*http.Cookie, user identity.UserID, address identity.IdentifierID, composed bool) {
	t.Helper()
	if len(cookies) != 1 {
		t.Fatal("real authenticated cookie unavailable")
	}
	token, err := session.ParseToken(cookies[0].Value)
	if err != nil {
		t.Fatal("real cookie malformed")
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("real current session unavailable", err)
	}
	binding, err := current.Session.Bindings()
	if err != nil || binding.UserID != user {
		t.Fatal("authentication selected wrong identity")
	}
	var queries emailQueryConsumer
	if composed {
		queries, err = features.EmailAddresses()
	} else {
		policy, policyErr := authorization.NewDecisionService(emailQueryConsumerPolicy{user: user})
		if policyErr != nil {
			t.Fatal(policyErr)
		}
		repository, repositoryErr := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
		if repositoryErr != nil {
			t.Fatal(repositoryErr)
		}
		c := referenceEmailQueryConfiguration()
		c.Native.Clock = clock.System{}
		queries, err = email.NewAddressQueryService(repository, policy, c.Redact, c.Native)
	}
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(binding.UserID)}, Action: "identity.email.address-list", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(binding.UserID)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	if current.ValidateAt(time.Now().UTC()) != nil {
		t.Fatal("original session evidence expired")
	}
	listed, err := queries.AddressList(ctx, email.AddressListRequest{TenantID: otpTenant, Caller: caller})
	if err != nil || listed.Outcome != identity.CommitOutcomeNotCommitted || len(listed.Addresses) != 1 || listed.NextCursor != "" {
		t.Fatal("native address list", err)
	}
	projection, err := listed.Addresses[0].Bindings()
	canonical, _, visible := listed.Addresses[0].Values()
	if err != nil || projection.IdentifierID != address || projection.UserID != user || projection.TenantID != otpTenant || !projection.Verified || projection.IdentifierVersion != 2 || projection.VerificationVersion != 2 || !visible || canonical != "registered@example.invalid" {
		t.Fatal("native verification history changed during projection")
	}
	caller.Request.Action = "identity.email.address-get"
	got, err := queries.AddressGet(ctx, email.AddressGetRequest{TenantID: otpTenant, AddressID: address, Caller: caller})
	if err != nil || got.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("native address get", err)
	}
	getBinding, err := got.Address.Bindings()
	if err != nil || getBinding.IdentifierID != projection.IdentifierID || getBinding.IdentifierVersion != projection.IdentifierVersion || getBinding.VerificationVersion != projection.VerificationVersion {
		t.Fatal("get lost original versions")
	}
	for _, absent := range []identity.IdentifierID{"unowned-address", address} {
		foreign := caller.Clone()
		if absent == address {
			foreign.Request.Tenant = "other"
		}
		out, err := queries.AddressGet(ctx, email.AddressGetRequest{TenantID: otpTenant, AddressID: absent, Caller: foreign})
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || out.Address != (identity.IdentifierProjection{}) {
			t.Fatal("native read existence disclosure", err)
		}
	}
}

// This is the bounded application policy seam. No role name or caller-provided
// administrative boolean grants permission; only exact self reads are selected.
type emailQueryConsumerPolicy struct{ user identity.UserID }

func (p emailQueryConsumerPolicy) Decide(_ context.Context, request authorization.Request) (authorization.Decision, error) {
	outcome := authorization.Deny
	if request.Tenant == otpTenant && request.Subject.Kind == authorization.SubjectUser && string(request.Subject.ID) == string(p.user) && request.Resource.Type == "identity.user" && string(request.Resource.ID) == string(p.user) && (request.Action == "identity.email.address-get" || request.Action == "identity.email.address-list") {
		outcome = authorization.Allow
	}
	return authorization.Decision{Outcome: outcome, Revision: 9}, nil
}
