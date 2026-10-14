package reference

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func TestReferencePostgresAdmissionConstructionAndOwnership(t *testing.T) {
	_, deps, _ := serverFixture(t)
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c := StoreConfiguration{DurableAdmission: &DurableAdmissionConfiguration{Schema: "risk_store", Namespace: "reference", Policy: policy, Keys: []risk.CounterDigestKey{key}, ReplayKey: bytes.Repeat([]byte{10}, 32), Tenants: []string{"tenant"}, MaximumRecords: 1000, Timeout: time.Second}}
	stores, err := ComposeStores(c, deps)
	if err != nil {
		t.Fatal("pure PostgreSQL-only graph rejected", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := stores.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	if _, err := stores.RecoverVelocity(t.Context(), "tenant"); err == nil {
		t.Fatal("durable profile selected ephemeral recovery")
	}
	c.Velocity.Schema = "duplicate_owner"
	if _, err := ComposeStores(c, deps); err == nil {
		t.Fatal("overlapping counter authority accepted")
	}
}
