//go:build integration

package passwordpostgres

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	email "github.com/faustbrian/go-identity/email"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
)

type registrationVerificationReader interface {
	ReadRegistrationVerification(context.Context, capability.Proof, authorization.DecisionContext) (email.RegistrationVerificationSpec, uint32, error)
}

type signupVerificationSender func(context.Context, delivery.Attempt) (delivery.DeliveryResult, error)

type signupVerificationWorkerPolicy struct{ revision authorization.Revision }

func (p signupVerificationWorkerPolicy) Decide(ctx context.Context, _ authorization.Request) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	return authorization.Decision{Outcome: authorization.Allow, Revision: p.revision}, nil
}

func (s signupVerificationSender) Send(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
	return s(ctx, a)
}

// This exercises the actual public signup and native delivery worker, not an
// invented token, application-owned store or substituted credential origin.
// Original live pre-auth state has already been removed by the parent fixture.
func testPublicSignupVerificationOrigin(t *testing.T, ctx context.Context, s *SignupService, c SignupConfig, request password.SignupRequest, command identity.CommandID) {
	t.Helper()
	reader, ok := any(s).(registrationVerificationReader)
	if !ok {
		t.Fatal("native signup owner has no authenticated registration verification origin read")
	}
	// The parent installed admission-only delivery. Select the public native
	// worker/policy/keyed/state forward history rather than private queue SQL.
	history, err := (deliverypg.MigrationSource{Base: kernel.MigrationSource{}, Version: 20, WorkerVersion: 23, PolicyVersion: 24, KeyedVersion: 25, StateVersion: 26}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range history {
		if migration.Version() > 20 {
			if _, err := s.pool.Raw().Exec(ctx, migration.UpSQL()); err != nil {
				t.Fatal("native verification worker forward history", err)
			}
		}
	}
	authz, err := authorization.NewDecisionService(signupVerificationWorkerPolicy{authorization.Revision(c.RequestKeys.Policy.PolicyVersion)})
	if err != nil {
		t.Fatal(err)
	}
	profile := delivery.DefaultConfig()
	profile.Production, profile.DedupeTTL = true, 25*time.Hour
	templates := []delivery.Template{{ID: "registration-verify", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "Verify: {{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{"https://auth.example.test"}, MaxRenderedBytes: 4096}}
	workerService, err := deliverypg.NewEnqueueService(ctx, s.pool, deliverypg.EnqueueConfig{
		Custody:     deliverypg.ContributorConfig{Deployment: "signup-test", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {67}}, ActiveEnvelopeKeyID: "input", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "mail", PolicyVersion: 1}}},
		Coordinator: c.Coordinator, PolicyID: c.PolicyID, PolicyVersion: c.RequestKeys.Policy.PolicyVersion,
		AuditRetentionVersion: 1, Timeout: 3 * time.Second, NamespaceKey: [32]byte{101},
		Policies: map[uint64]delivery.Config{1: profile}, StateTracking: true,
	}, s.crypto, authz, templates)
	if err != nil {
		t.Fatal("native verification delivery composition", err)
	}
	var proof capability.Proof
	calls := 0
	worker, err := workerService.NewWorker(deliverypg.WorkerConfig{Scope: authorization.DecisionContext{PolicyRevision: authorization.Revision(c.RequestKeys.Policy.PolicyVersion), CorrelationID: "verification-worker", Request: authorization.Request{Tenant: authorization.TenantID(request.TenantID), Action: "identity.delivery.process", Subject: authorization.Subject{ID: "verification-worker", Kind: authorization.SubjectServiceAccount}, Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "verification-worker"}}}, ProviderConfigVersion: 1}, signupVerificationSender(func(_ context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
		// Earlier native composition cases enqueue their own original messages.
		// Drain through the actual worker, never select/mutate its queue with SQL.
		if a.Recipient != string(request.Email) {
			return delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}, nil
		}
		calls++
		if !strings.HasPrefix(string(a.Body), "Verify: ") {
			t.Error("worker changed original signup verification message")
		}
		link, parseErr := url.Parse(strings.TrimPrefix(string(a.Body), "Verify: "))
		if parseErr != nil {
			t.Error("invalid native verification link")
		} else {
			proof, parseErr = capability.ParseProof(link.Query().Get("token"), capability.DefaultLimits())
			if parseErr != nil {
				t.Error("invalid delivered original proof")
			}
		}
		return delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 16 && calls == 0; n++ {
		processed, err := worker.ProcessOne(ctx)
		if err != nil || !processed.Claimed || processed.Completion.State != delivery.StateDelivered {
			t.Fatal("native original verification delivery failed", err)
		}
	}
	if calls != 1 {
		t.Fatal("native worker did not deliver original public signup")
	}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(c.Coordinator.QueryPolicy.PolicyVersion), CorrelationID: "verification-read", Request: authorization.Request{Tenant: authorization.TenantID(request.TenantID), Action: "identity.email.verification-confirm", Subject: authorization.Subject{ID: "confirmation-service", Kind: authorization.SubjectServiceAccount}, Resource: authorization.Resource{Type: "identity.user"}}}
	grant, origin, replayVersion, err := c.Verification.Issuer.ReadRegistrationOrigin(ctx, s.pool, proof)
	if err != nil || origin != command || replayVersion == 0 {
		t.Fatal("native proof lost committed original signup", err)
	}
	caller.Request.Resource.ID = authorization.ResourceID(grant.Payload().Subject)
	for n := 0; n < 2; n++ {
		spec, version, err := reader.ReadRegistrationVerification(ctx, proof, caller)
		if err != nil || version != replayVersion || spec.Binding.CommandID != command || spec.Binding.ActorID != identity.ActorID(request.Caller.Request.Subject.ID) || spec.Payload.SubjectID != identity.SubjectID(grant.Payload().Subject) || spec.Payload.CanonicalAddress.Record().Value != string(request.Email) || c.Verification.Policy.Authorize(grant, spec, time.Now().UTC()) != nil {
			t.Fatal("original encrypted verification intent was not authenticated", err)
		}
	}
	var wait sync.WaitGroup
	failures := make([]error, 4)
	for n := range failures {
		wait.Add(1)
		go func(n int) {
			defer wait.Done()
			_, _, failures[n] = reader.ReadRegistrationVerification(ctx, proof, caller)
		}(n)
	}
	wait.Wait()
	for _, err := range failures {
		if err != nil {
			t.Fatal("concurrent original verification read failed", err)
		}
	}
	for _, change := range []func(*authorization.DecisionContext){
		func(q *authorization.DecisionContext) { q.Request.Tenant = "foreign-tenant" },
		func(q *authorization.DecisionContext) { q.Request.Action = "identity.password.signup" },
		func(q *authorization.DecisionContext) { q.Request.Resource.ID = "foreign-user" },
	} {
		wrong := caller
		change(&wrong)
		spec, version, err := reader.ReadRegistrationVerification(ctx, proof, wrong)
		if err == nil || version != 0 || spec.Binding.CommandID != "" {
			t.Fatal("foreign confirmation context disclosed original input")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	spec, version, err := reader.ReadRegistrationVerification(cancelled, proof, caller)
	if err == nil || version != 0 || spec.Binding.CommandID != "" {
		t.Fatal("cancelled confirmation retained input")
	}
	spec, version, err = reader.ReadRegistrationVerification(ctx, capability.Proof{}, caller)
	if err == nil || version != 0 || spec.Binding.CommandID != "" {
		t.Fatal("zero proof disclosed original input")
	}
	// An unchanged read never verifies the mailbox or consumes the issued proof.
	var issued, unverified bool
	if err := s.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.capability_identity_one_use WHERE tenant_id=$1 AND capability_id=$2 AND state='issued' AND uses=0),EXISTS(SELECT 1 FROM identity.identifiers WHERE tenant_id=$1 AND identifier_id=$3 AND NOT verified AND verification_state=1 AND verified_at IS NULL)`, grant.Payload().Tenant, grant.Payload().ID, grant.Payload().Resource).Scan(&issued, &unverified); err != nil || !issued || !unverified {
		t.Fatal("origin read mutated verification or consumed authority", err)
	}
}
