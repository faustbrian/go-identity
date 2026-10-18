//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/username"
	database "github.com/faustbrian/go-postgres"
)

// Continue the genuinely registered/confirmed username fixture, using native
// PostgreSQL for occupancy, quotas and canonical audit. Only normalized policy
// observations use the declared callback seam; no stores or decisions are fake.
func testNativeUsernameAvailability(t *testing.T, ctx context.Context, pool *database.Pool, signup SignupConfig, original password.SignupRequest) {
	started := time.Now().UTC().Truncate(time.Microsecond)
	history, err := (riskpg.DurableCounterMigrationSource{Schema: "username_availability_risk", Version: 1}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal("durable availability quota history", err)
		}
	}
	profiles := []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 3, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2},
	}
	for n := range profiles {
		profiles[n].RequiredSignals = []string{"status", "velocity"}
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Profiles: profiles, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	policyID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	makeService := func(namespace string, state risk.SignalState, p *username.Policy) *UsernameAvailabilityService {
		t.Helper()
		service, err := NewUsernameAvailabilityService(pool, p, UsernameAvailabilityConfig{Domain: kernel.UsernameRenameDomainConfig{NormalizationProfile: string(username.ProfileID), NormalizationVersion: username.ProfileVersion, CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}, ReuseCooldown: 30 * 24 * time.Hour}, Counters: riskpg.DurableCounterConfig{Pool: pool, Schema: "username_availability_risk", Namespace: namespace, Policy: policy, Keys: []risk.CounterDigestKey{key}, ReplayKey: bytes.Repeat([]byte{72}, 32), Tenants: []string{string(original.TenantID)}, MaximumRecords: 1000, Timeout: time.Second}, Sources: []risk.Source{{Name: "status", Version: "availability-policy-v1", Timeout: time.Second, Read: func(_ context.Context, c risk.Context) (risk.Signal, error) {
			return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: state, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(time.Minute)}, nil
		}}}, PolicyID: string(policyID), MaximumDuration: 3 * time.Second, RiskTimeout: 2 * time.Second, OnAuditLoss: func(context.Context, risk.DecisionDelivery) error { return nil }})
		if err != nil {
			t.Fatal("native availability composition", err)
		}
		return service
	}
	request := username.AvailabilityRequest{TenantID: string(original.TenantID), Username: "STRASSE", Network: "2001:db8::71"}
	p, err := username.NewPolicy(username.ReferencePolicySpec())
	if err != nil {
		t.Fatal(err)
	}
	service := makeService("availability-normal", risk.SignalClean, p)
	// Caller replacement cannot change this service's already frozen enrollment.
	reject := username.ReferencePolicySpec()
	reject.Validators = []username.Validator{func(context.Context, username.Name) error { return username.ErrValidation }}
	replacement, err := username.NewPolicy(reject)
	if err != nil {
		t.Fatal(err)
	}
	*p = *replacement
	for _, candidate := range []string{"STRASSE", "unreserved", "Straße"} {
		request.Username = candidate
		result, err := service.Available(ctx, request)
		if err != nil || result.Available != (candidate == "unreserved") {
			t.Fatal("public advisory availability disagrees with real canonical reservation", err)
		}
	}
	request.Username = "unreserved"
	result, err := service.Available(ctx, request)
	if !errors.Is(err, username.ErrThrottled) || result.Available {
		t.Fatal("fourth request bypassed actual durable quota", err)
	}
	var attempts int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM username_availability_risk.durable_counter_attempts WHERE namespace='availability-normal'`).Scan(&attempts); err != nil || attempts != 4 {
		t.Fatal("availability reused client-independent attempt or failed to charge", err)
	}
	for _, test := range []struct {
		namespace string
		state     risk.SignalState
	}{{"availability-denied", risk.SignalDeny}, {"availability-unknown", risk.SignalUnavailable}} {
		p, _ := username.NewPolicy(username.ReferencePolicySpec())
		denied := makeService(test.namespace, test.state, p)
		if result, err := denied.Available(ctx, request); err == nil || result.Available {
			t.Fatal("unknown/denied status disclosed availability")
		}
	}
	p, _ = username.NewPolicy(username.ReferencePolicySpec())
	storage := makeService("availability-storage", risk.SignalClean, p)
	if _, err := pool.Raw().Exec(ctx, `ALTER TABLE identity.identifiers RENAME TO availability_hidden_identifiers`); err != nil {
		t.Fatal(err)
	}
	result, err = storage.Available(ctx, request)
	if _, restore := pool.Raw().Exec(ctx, `ALTER TABLE identity.availability_hidden_identifiers RENAME TO identifiers`); restore != nil {
		t.Fatal("restore owned failure fixture", restore)
	}
	if !errors.Is(err, username.ErrUnavailable) || result.Available {
		t.Fatal("unavailable primary became an available username", err)
	}
	if result, err := storage.Available(ctx, request); err != nil || !result.Available {
		t.Fatal("restored native authority remained unusable", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if result, err := storage.Available(canceled, request); !errors.Is(err, context.Canceled) || result.Available {
		t.Fatal("canceled request disclosed an observation", err)
	}
	auditing := makeService("availability-audit", risk.SignalClean, p)
	if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION audit.fail_availability_decision() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic private audit failure'; END $$; CREATE TRIGGER fail_availability_decision BEFORE INSERT ON audit.records FOR EACH ROW EXECUTE FUNCTION audit.fail_availability_decision()`); err != nil {
		t.Fatal("audit failure fixture", err)
	}
	result, err = auditing.Available(ctx, request)
	if _, restore := pool.Raw().Exec(ctx, `DROP TRIGGER fail_availability_decision ON audit.records; DROP FUNCTION audit.fail_availability_decision()`); restore != nil {
		t.Fatal("restore native audit owner", restore)
	}
	if !errors.Is(err, username.ErrUnavailable) || result.Available {
		t.Fatal("unacknowledged required audit disclosed availability", err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM username_availability_risk.durable_counter_attempts WHERE namespace='availability-audit'`).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatal("audit failure erased/retried durable rate debit", err)
	}
	if _, err := pool.Raw().Exec(ctx, `ALTER TABLE username_availability_risk.durable_counter_windows RENAME TO unavailable_counter_windows`); err != nil {
		t.Fatal(err)
	}
	result, err = auditing.Available(ctx, request)
	if _, restore := pool.Raw().Exec(ctx, `ALTER TABLE username_availability_risk.unavailable_counter_windows RENAME TO durable_counter_windows`); restore != nil {
		t.Fatal("restore native counter owner", restore)
	}
	if err == nil || result.Available {
		t.Fatal("unavailable durable counter disclosed availability")
	}
	sink, err := auditpg.New(pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := audit.Tenant(string(original.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	query, err := audit.NewQuery(audit.QueryInput{Tenant: tenant, From: started, Action: "identity.risk.decide", Limit: 32})
	if err != nil {
		t.Fatal(err)
	}
	page, err := sink.Query(ctx, query)
	if err != nil || len(page.Records) != 9 {
		t.Fatal("native availability omitted required canonical decisions", err)
	}
	for _, record := range page.Records {
		if record.Policy().PolicyID != string(policyID) {
			t.Fatal("audit query included a foreign decision")
		}
		wire, err := audit.CanonicalJSON(record)
		if err != nil || bytes.Contains(wire, []byte("Straße")) || bytes.Contains(wire, []byte("STRASSE")) || bytes.Contains(wire, []byte("unreserved")) || bytes.Contains(wire, []byte(request.Network)) {
			t.Fatal("availability audit disclosed candidate/network", err)
		}
	}
}
