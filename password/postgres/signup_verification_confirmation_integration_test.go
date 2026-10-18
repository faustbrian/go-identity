//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/username"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// Actual public signup, delivered signed proof, original encrypted intent,
// native capability/counters/kernel/audit/outbox all run. Only the caller's
// authorized email sender and startup access policy are injected boundaries.
func testPublicRegistrationConfirmation(t *testing.T, ctx context.Context, source *SignupService, c SignupConfig, keys *keyring.Provider, proof capability.Proof, deliveredToken, callback string, caller authorization.DecisionContext, grant capability.Grant) {
	t.Helper()
	const schema = "registration_confirmation_risk"
	for _, migrationSource := range []migrations.Source{
		kernel.EmailVerificationMigrationSource{Base: kernel.MigrationSource{}, Version: 40},
		riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: schema, Version: 41}, Version: 42}, Version: 43}, Version: 44},
		riskpg.VerificationCounterMigrationSource{Schema: schema, Version: 45},
	} {
		if c.Username != nil {
			if _, registration := migrationSource.(kernel.EmailVerificationMigrationSource); registration {
				// The username consumer installed the real predecessor and forward
				// purpose extension before its original registration.
				continue
			}
		}
		history, err := migrationSource.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range history {
			if item.Version() >= 40 {
				if _, err := source.pool.Raw().Exec(ctx, item.UpSQL()); err != nil {
					t.Fatal("confirmation forward history", err)
				}
			}
		}
	}
	profiles := []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2},
	}
	for n := range profiles {
		profiles[n].RequiredSignals = []string{"status", "velocity"}
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: c.Coordinator.AdmissionPolicy.PolicyVersion, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: profiles})
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{107}, 32))
	evidence, _ := risk.NewEvidenceKey(1, bytes.Repeat([]byte{108}, 32), bytes.Repeat([]byte{109}, 32))
	c.Verification.Counters, err = riskpg.NewRepository(riskpg.Config{Schema: schema, PolicyVersion: c.Coordinator.AdmissionPolicy.PolicyVersion, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"wrap": bytes.Repeat([]byte{110}, 32)}, CurrentEnvelopeKey: "wrap", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: []risk.CounterDigestKey{digest}}})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewSignupService(source.pool, c, keys)
	if err != nil {
		t.Fatal(err)
	}
	// Coexisting registration profiles have distinct encrypted input ownership.
	// The shared route must select the authenticated original, not try one owner
	// and fall back after its query/decryption fails.
	alternate := c
	if c.Username == nil {
		alternate.Username, err = username.NewPolicy(username.ReferencePolicySpec())
		if err != nil {
			t.Fatal(err)
		}
	} else {
		alternate.Username = nil
	}
	alternateOwner, err := NewSignupService(source.pool, alternate, keys)
	if err != nil {
		t.Fatal("coexisting registration owner", err)
	}
	emailOwner, usernameOwner := service, alternateOwner
	if c.Username != nil {
		emailOwner, usernameOwner = alternateOwner, service
	}
	router, err := NewRegistrationVerificationRouter(emailOwner, usernameOwner, nil)
	if err != nil {
		t.Fatal("coexisting registration router", err)
	}
	if _, err := NewRegistrationVerificationRouter(usernameOwner, emailOwner, nil); err == nil {
		t.Fatal("registration router accepted swapped profile owners")
	}
	owner, ok := any(service).(registrationVerificationConfirmer)
	if !ok {
		t.Fatal("native signup owner has no explicit registration confirmation")
	}
	rateSource, ok := any(service).(registrationVerificationRateSource)
	if !ok {
		t.Fatal("native confirmation has no original rate-source port")
	}
	assertRateSource := func() {
		t.Helper()
		unselected := caller
		unselected.Request.Resource.ID = ""
		user, challenge, lifetime, err := rateSource.RegistrationVerificationRateSource(ctx, proof, callback, unselected)
		original := grant.Payload()
		if err != nil || user != identity.UserID(original.Subject) || challenge != original.ID || lifetime != original.ExpiresAt.Sub(original.IssuedAt) {
			t.Fatal("rate source lost authenticated original grant", err)
		}
	}
	assertRateSource()
	if user, challenge, lifetime, err := router.VerificationRateSource(ctx, proof, callback, caller); err != nil || user != identity.UserID(grant.Payload().Subject) || challenge != grant.Payload().ID || lifetime != grant.Payload().ExpiresAt.Sub(grant.Payload().IssuedAt) {
		t.Fatal("shared route lost original registration profile", err)
	}
	for _, change := range []func(*authorization.DecisionContext, *string){
		func(_ *authorization.DecisionContext, target *string) {
			*target = "https://foreign.example.test/finish"
		},
		func(c *authorization.DecisionContext, _ *string) { c.Request.Resource.ID = "foreign-user" },
		func(c *authorization.DecisionContext, _ *string) { c.Request.Tenant = "foreign-tenant" },
		func(c *authorization.DecisionContext, _ *string) { c.PolicyRevision++ },
	} {
		wrong, target := caller, callback
		change(&wrong, &target)
		user, challenge, lifetime, err := rateSource.RegistrationVerificationRateSource(ctx, proof, target, wrong)
		if err == nil || user != "" || challenge != "" || lifetime != 0 {
			t.Fatal("foreign rate source disclosed original binding")
		}
		if user, challenge, lifetime, err := router.VerificationRateSource(ctx, proof, target, wrong); err == nil || user != "" || challenge != "" || lifetime != 0 {
			t.Fatal("profiled rate source disclosed foreign original binding")
		}
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if user, challenge, lifetime, err := rateSource.RegistrationVerificationRateSource(canceled, proof, callback, caller); err == nil || user != "" || challenge != "" || lifetime != 0 {
		t.Fatal("canceled rate source disclosed original binding")
	}
	if user, challenge, lifetime, err := router.VerificationRateSource(canceled, proof, callback, caller); err == nil || user != "" || challenge != "" || lifetime != 0 {
		t.Fatal("canceled profiled source disclosed original binding")
	}
	id, _ := identity.NewCommandID()
	if result, err := owner.ConfirmRegistrationVerification(ctx, proof, "https://foreign.example.test/finish", id, "2001:db8::1", caller); err == nil || result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("foreign callback confirmed original address")
	}
	wrong := caller
	wrong.Request.Resource.ID = "foreign-user"
	if result, err := owner.ConfirmRegistrationVerification(ctx, proof, callback, id, "2001:db8::1", wrong); err == nil || result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("foreign subject confirmed original address")
	}
	typed, ok := any(service).(email.RegistrationVerificationService)
	if !ok {
		t.Fatal("native owner has no typed email service binding")
	}
	redirect, err := url.Parse(callback)
	if err != nil {
		t.Fatal(err)
	}
	request := email.VerificationConfirmRequest{TenantID: identity.TenantID(grant.Payload().Tenant), CommandID: id, Token: proof, Callback: *redirect, Network: "2001:db8::1", Caller: caller}
	original, _, err := service.ReadRegistrationVerification(ctx, proof, caller)
	if err != nil {
		t.Fatal("original confirmation intent unavailable", err)
	}
	testRegistrationConfirmationHTTP(t, ctx, service, c, deliveredToken, callback, original.Payload.CanonicalAddress.Record().Value, caller, grant, id, router)
	confirmed, err := typed.VerificationConfirm(ctx, request)
	if err != nil || confirmed.Validate() != nil || confirmed.Outcome != identity.CommitOutcomeCommitted || !confirmed.Replayed || confirmed.Address != (identity.IdentifierProjection{}) {
		t.Fatal("typed recovery of HTTP confirmation re-disclosed address", confirmed.Outcome, err)
	}
	typedReplay, err := typed.VerificationConfirm(ctx, request)
	if err != nil || typedReplay.Validate() != nil || !typedReplay.Replayed || typedReplay.Address != (identity.IdentifierProjection{}) {
		t.Fatal("typed replay re-disclosed address", err)
	}
	// Consumed provenance can be counted for original replay; it does not grant
	// reuse. The existing second-command and scanner denials below still apply.
	assertRateSource()
	result, err := owner.ConfirmRegistrationVerification(ctx, proof, callback, id, "2001:db8::1", caller)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Feature == nil || result.Feature.AfterVersion != 2 {
		t.Fatal("native delivered signup proof did not confirm atomically", result.Outcome, err)
	}
	replayed, err := owner.ConfirmRegistrationVerification(ctx, proof, callback, id, "2001:db8::1", caller)
	if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || replayed.Binding != result.Binding || replayed.Feature.AfterVersion != result.Feature.AfterVersion {
		t.Fatal("same confirmation command did not preserve original receipt", err)
	}
	recovery, ok := any(service).(registrationVerificationRecovery)
	if !ok {
		t.Fatal("native registration confirmation has no proof-free recovery")
	}
	query := identity.RecoveryQuery{CommandID: id, TenantID: result.Binding.TenantID, UserID: result.Binding.UserID, ActorID: result.Binding.ActorID, ActorKind: result.Binding.ActorKind, OperationID: result.Binding.OperationID, RecordID: result.Binding.RecordID}
	typedRecovered, err := typed.VerificationRecover(ctx, email.VerificationRecoveryRequest{Recovery: confirmed.Recovery, Caller: caller})
	if err != nil || typedRecovered.Validate() != nil || typedRecovered.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("typed proof-free recovery lost commitment", err)
	}
	bindings, err := typedRecovered.Recovery.Bindings()
	if err != nil || bindings != query {
		t.Fatal("typed recovery retargeted command", err)
	}
	recovered, err := recovery.RecoverRegistrationVerification(ctx, query, caller)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Binding != result.Binding || recovered.Feature.AfterVersion != 2 {
		t.Fatal("proof-free original confirmation recovery diverged", err)
	}
	foreignQuery := query
	foreignQuery.RecordID = "foreign-address"
	if result, err := recovery.RecoverRegistrationVerification(ctx, foreignQuery, caller); err == nil || result.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("foreign address disclosed confirmation history")
	}
	other, _ := identity.NewCommandID()
	if result, err := owner.ConfirmRegistrationVerification(ctx, proof, callback, other, "2001:db8::1", caller); err == nil || result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("consumed registration proof confirmed a second command")
	}
	if valid, err := service.ValidateRegistrationVerification(ctx, proof, callback, caller); err == nil || valid {
		t.Fatal("consumed proof still passed scanner validation")
	}
	state, err := service.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: identity.TenantID(grant.Payload().Tenant), UserID: identity.UserID(grant.Payload().Subject), MaximumIdentifiers: 128})
	verified, verification := false, false
	for _, actual := range state.Identifiers {
		if string(actual.ID) == grant.Payload().Resource {
			verified = actual.Verified && actual.Version == 2 && actual.Kind == identity.IdentifierEmail
		} else if actual.Kind != identity.IdentifierUsername || actual.Verified || actual.Version != 1 {
			t.Fatal("confirmation changed supplementary username")
		}
	}
	for _, actual := range state.Verifications {
		if string(actual.IdentifierID) == grant.Payload().Resource {
			verification = actual.Version == 2
		}
	}
	if err != nil || !verified || !verification || state.User.Version != 2 || state.AuthorityVersion != 2 {
		t.Fatal("confirmation lost exact pending-address transition", err)
	}
	var consumed, retained bool
	var charges int
	if err := service.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.capability_identity_one_use WHERE tenant_id=$1 AND capability_id=$2 AND state='finalized' AND uses=1),EXISTS(SELECT 1 FROM identity.email_verifications WHERE command_id=$3),(SELECT count(*) FROM registration_confirmation_risk.counter_charges WHERE tenant_id=$1)`, grant.Payload().Tenant, grant.Payload().ID, string(id)).Scan(&consumed, &retained, &charges); err != nil || !consumed || !retained || charges != 1 {
		t.Fatal("confirmation proof/effect/replayed charge diverged", err)
	}
}
