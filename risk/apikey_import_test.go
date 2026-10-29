package risk

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestLegacyAPIKeyImportRequiresOriginalProtectedAdmission(t *testing.T) {
	configuration := testPolicyConfig()
	configuration.Profiles[1].RequiredSignals = []string{"velocity", "status", "captcha"}
	policy, err := NewPolicy(configuration)
	if err != nil {
		t.Fatal(err)
	}
	c := testContext()
	c.Operation = "identity.apikey.import"
	admission, err := policy.Admit(c.Operation)
	if err != nil || admission.Profile.Class != CredentialMutation || admission.Profile.Phase != ReserveWithCommand || admission.Preflight != "" {
		t.Fatal("digest-only import lacks its existing protected mutation profile", err)
	}
	facts := []Signal{testSignal(c, "status", SignalClean), testSignal(c, "captcha", SignalClean)}
	ordinary, err := policy.Assess(t.Context(), c, facts)
	if err != nil || ordinary.Decision.Action != Deny {
		t.Fatal("import bypassed ordinary velocity", err)
	}
	providers, err := policy.AssessProtectedProviders(t.Context(), c, facts)
	if err != nil || providers.Decision.Action != Allow {
		t.Fatal("import cannot defer velocity to its owning transaction", err)
	}
	for _, state := range []SignalState{SignalDeny, SignalUnknown, SignalUnavailable, SignalStepUp} {
		facts[0].State = state
		assessment, err := policy.AssessProtectedProviders(t.Context(), c, facts)
		if err != nil || assessment.Decision.Action == Allow {
			t.Fatal("required import provider failure admitted", state, err)
		}
	}
	facts[0].State = SignalClean
	if assessment, err := policy.AssessProtectedProviders(t.Context(), c, facts[:1]); err != nil || assessment.Decision.Action != Deny {
		t.Fatal("omitted import signal admitted", err)
	}
	key, err := NewCounterDigestKey(1, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counters, err := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: policy, Keys: []CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{User: "existing-owner", Session: "original-session", Network: "192.0.2.1"}
	command, err := counters.Prepare(c, subject, c.Now)
	if err != nil || counters.Validate(command, c, subject, c.Now) != nil {
		t.Fatal("import cannot reserve exact original counters", err)
	}
	b := command.Bindings()
	if b.Phase != ReserveWithCommand || b.Window != 15*time.Minute || b.Limit != 5 || len(b.Targets) != 4 {
		t.Fatal("import weakened the credential mutation budget")
	}
	for _, change := range []func(*Context, *Subject){
		func(c *Context, _ *Subject) { c.Operation = "identity.apikey.create" },
		func(c *Context, _ *Subject) { c.Tenant = "foreign" },
		func(c *Context, _ *Subject) { c.Attempt = "other-original" },
		func(_ *Context, s *Subject) { s.User = "other-owner" },
		func(_ *Context, s *Subject) { s.Session = "other-session" },
		func(_ *Context, s *Subject) { s.Network = "192.0.2.2" },
	} {
		changed, owner := c, subject
		change(&changed, &owner)
		if counters.Validate(command, changed, owner, c.Now) == nil {
			t.Fatal("import counter projection transferred to another scope")
		}
	}
	if counters.Validate(command, c, subject, c.Now.Add(15*time.Minute)) == nil {
		t.Fatal("import renewed original counter expiry")
	}
	ephemeral := testCounterCoordinator(t, counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) {
		t.Fatal("protected import reached ephemeral counter authority")
		return CounterResult{}, nil
	}))
	if _, err := ephemeral.Mutate(t.Context(), command); err == nil {
		t.Fatal("ephemeral counter owner accepted protected import")
	}
	for _, action := range []Action{"identity.apikey.Import", "identity.apikey.import ", "identity.apikey.import-prepare", "identity.apikey.import.recover"} {
		c.Operation = action
		if _, err := counters.Prepare(c, subject, c.Now); err == nil {
			t.Fatal("unselected import alias acquired counters")
		}
	}
}
