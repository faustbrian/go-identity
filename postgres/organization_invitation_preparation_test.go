package postgres

import (
	"bytes"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestOrganizationInvitationPreparationHistoryRequiresExactOriginalDeclaration(t *testing.T) {
	b, p := organizationInvitationSendPlanFixture(t)
	fp := [32]byte{1}
	wire, err := encodeFeaturePlan(b, fp, p)
	if err != nil {
		t.Fatal(err)
	}
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation})
	claim, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	until, state, profile := now.Add(time.Second), "pending", int16(3)
	observed := commandObservation{tenant: string(b.TenantID), purpose: b.OperationID, scope: claim.safeFields, fingerprint: fp[:], state: &state, until: &until, now: now, preparationProfile: &profile, declaration: wire}
	q, _ := queryInputs(b)
	result, err := commandReceipt(q, observed, nil)
	if err != nil || result.Outcome != identity.CommitOutcomeInProgress || result.Binding != b {
		t.Fatal("original invitation history unavailable", err)
	}
	for name, mutate := range map[string]func(*commandObservation){
		"missing":           func(o *commandObservation) { o.declaration = nil },
		"truncated":         func(o *commandObservation) { o.declaration = wire[:len(wire)-1] },
		"trailing":          func(o *commandObservation) { o.declaration = append(bytes.Clone(wire), 0) },
		"wrong-fingerprint": func(o *commandObservation) { o.fingerprint = bytes.Repeat([]byte{2}, 32) },
		"missing-profile":   func(o *commandObservation) { o.preparationProfile = nil },
		"ordinary-profile":  func(o *commandObservation) { v := int16(1); o.preparationProfile = &v },
		"committed":         func(o *commandObservation) { v := "committed"; o.state = &v },
		"empty-final-plan":  func(o *commandObservation) { o.plan = []byte{} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := observed
			mutate(&bad)
			if result, err := commandReceipt(q, bad, nil); err == nil || result.Outcome != identity.CommitOutcomeInvalid {
				t.Fatal("incomplete preparation supplied an outcome")
			}
		})
	}
	for name, mutate := range map[string]func(*CommandPlan){
		"wrong-subject":   func(p *CommandPlan) { p.SubjectType = "organization" },
		"wrong-lifecycle": func(p *CommandPlan) { p.Lifecycle.BeforeVersion, p.Lifecycle.AfterVersion = 1, 2 },
		"missing-counter": func(p *CommandPlan) { p.CommandCounters = nil },
		"issuance":        func(p *CommandPlan) { p.CapabilityIssuance = issuanceTestPlan() },
		"delivery":        func(p *CommandPlan) { p.Delivery = deliveryTestPlan() },
		"wrong-audit":     func(p *CommandPlan) { p.Audits[0].RetentionClass = "standard" },
	} {
		t.Run(name, func(t *testing.T) {
			_, bad := organizationInvitationSendPlanFixture(t)
			mutate(&bad)
			if validOrganizationInvitationPreparation(b, bad) {
				t.Fatal("foreign/generated declaration admitted as original preparation")
			}
		})
	}
}
