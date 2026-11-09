package postgres

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestAccountLinkStatePlanPreservesOAuthAuditActions(t *testing.T) {
	_, command, p := accountLinkOwnerPlanFixture(t)
	spec, _, _ := command.AccountLinkCounterCommand()
	state := *p.Capability
	state.Purpose, state.CapabilityID = "identity.oauth.callback", "original-state"
	state.ReplayDigest, state.ProofFingerprint = [32]byte{8}, [32]byte{9}
	p.AccountLinkState = &state
	for i, action := range []string{"identity.oauth.handle_callback", "identity.oauth.link_account"} {
		plan := p.Audits[0]
		plan.EventType, plan.EventIndex = action, uint16(i+1)
		p.Audits = append(p.Audits, plan)
	}
	wire, err := encodeKernelPlan(spec.Binding, [32]byte{1}, p)
	if err != nil {
		t.Fatal("composed callback cannot declare its required audit actions", err)
	}
	got, err := decodeKernelPlan(spec.Binding, [32]byte{1}, wire)
	if err != nil || !reflect.DeepEqual(got.Audits, p.Audits) {
		t.Fatal("callback audit actions did not survive durable plan history", err)
	}
	for n := range wire {
		if _, err := decodeKernelPlan(spec.Binding, [32]byte{1}, wire[:n]); err == nil {
			t.Fatal("truncated composed callback audit history admitted")
		}
	}
	for _, mutate := range []func([]AuditPlan) []AuditPlan{
		func(plans []AuditPlan) []AuditPlan { return plans[:2] },
		func(plans []AuditPlan) []AuditPlan { plans[1].EventType = "identity.oauth.signin"; return plans },
		func(plans []AuditPlan) []AuditPlan { plans[2].RetentionClass = "protected"; return plans },
		func(plans []AuditPlan) []AuditPlan { plans[2].EventIndex = plans[1].EventIndex; return plans },
		func(plans []AuditPlan) []AuditPlan { plans[1].BindingDigest = [32]byte{17}; return plans },
	} {
		invalid := p
		invalid.Audits = mutate(append([]AuditPlan(nil), p.Audits...))
		if _, err := encodeKernelPlan(spec.Binding, [32]byte{1}, invalid); err == nil {
			t.Fatal("changed OAuth audit action, retention, scope or slot admitted")
		}
	}
}

func TestAccountLinkStatePlanRetainsBothInputsWithoutChangingLegacyBytes(t *testing.T) {
	_, command, original := accountLinkOwnerPlanFixture(t)
	spec, _, _ := command.AccountLinkCounterCommand()
	fingerprint := [32]byte{7}
	legacy, err := encodeKernelPlan(spec.Binding, fingerprint, original)
	if err != nil {
		t.Fatal(err)
	}
	state := *original.Capability
	state.Purpose, state.CapabilityID = "identity.oauth.callback", "original-state"
	state.ReplayDigest, state.ProofFingerprint = [32]byte{8}, [32]byte{9}
	prepared := original
	prepared.AccountLinkState = &state
	for _, beforeExchange := range []bool{true, false} {
		selected := prepared
		if beforeExchange {
			selected.Capability = nil
		}
		wire, err := encodeKernelPlan(spec.Binding, fingerprint, selected)
		if err != nil {
			t.Fatal("closed original-state profile rejected", beforeExchange, err)
		}
		decoded, err := decodeKernelPlan(spec.Binding, fingerprint, wire)
		if err != nil || decoded.AccountLinkState == nil || !reflect.DeepEqual(*decoded.AccountLinkState, state) || (decoded.Capability == nil) != beforeExchange || !reflect.DeepEqual(decoded.Contributors, original.Contributors) {
			t.Fatal("preparation stage or distinct immutable inputs lost", err)
		}
		if decoded.Capability != nil && !reflect.DeepEqual(*decoded.Capability, *original.Capability) {
			t.Fatal("final canonical link grant replaced original state")
		}
		for index := range wire {
			if _, err := decodeKernelPlan(spec.Binding, fingerprint, wire[:index]); err == nil {
				t.Fatal("truncated state plan accepted")
			}
		}
		if _, err := decodeKernelPlan(spec.Binding, fingerprint, append(bytes.Clone(wire), 0)); err == nil {
			t.Fatal("trailing state plan bytes accepted")
		}
	}
	for _, mutate := range []func(*CommandPlan){
		func(p *CommandPlan) {
			copy := *p.AccountLinkState
			copy.Purpose = "identity.password.reset-complete"
			p.AccountLinkState = &copy
		},
		func(p *CommandPlan) { copy := *p.AccountLinkState; copy.MaxUses = 2; p.AccountLinkState = &copy },
		func(p *CommandPlan) {
			copy := *p.AccountLinkState
			copy.ProofFingerprint = [32]byte{}
			p.AccountLinkState = &copy
		},
		func(p *CommandPlan) {
			copy := *p.AccountLinkState
			copy.ReplayKeyVersion = 0
			p.AccountLinkState = &copy
		},
		func(p *CommandPlan) { p.CommandCounters = nil },
		func(p *CommandPlan) { p.Contributors = p.Contributors[:5] },
		func(p *CommandPlan) {
			p.Contributors = append([]ContributorDescriptor(nil), p.Contributors...)
			p.Contributors[0], p.Contributors[1] = p.Contributors[1], p.Contributors[0]
		},
	} {
		selected := prepared
		mutate(&selected)
		if _, err := encodeKernelPlan(spec.Binding, fingerprint, selected); err == nil {
			t.Fatal("invalid or incomplete original state plan accepted")
		}
	}
	wrong := spec.Binding
	wrong.LinkMode = identity.AccountLinkAdministrative
	if _, err := encodeKernelPlan(wrong, fingerprint, prepared); err == nil {
		t.Fatal("state profile widened beyond explicit self-link")
	}
	prepared.AccountLinkState = nil
	again, err := encodeKernelPlan(spec.Binding, fingerprint, prepared)
	if err != nil || !bytes.Equal(again, legacy) {
		t.Fatal("new state profile changed historical ordinary account-link bytes", err)
	}
}

func TestAccountLinkStateDeclarationCannotEnableOrdinaryExecution(t *testing.T) {
	c, command, plan := accountLinkOwnerPlanFixture(t)
	spec, _, _ := command.AccountLinkCounterCommand()
	state := *plan.Capability
	state.Purpose, state.CapabilityID = "identity.oauth.callback", "original-state"
	state.ReplayDigest, state.ProofFingerprint = [32]byte{8}, [32]byte{9}
	plan.AccountLinkState = &state
	if _, err := c.PrepareCommandPlan(spec.Binding, command, plan); err == nil {
		t.Fatal("state declaration enabled link execution before native preparation phases exist")
	}
}

func FuzzAccountLinkStatePlanDecoder(f *testing.F) {
	b := codecBinding()
	b.OperationID, b.SchemaID, b.SchemaVersion, b.RecordID, b.LinkMode = "identity.account.link-token", "identity-account", 1, "account-a", identity.AccountLinkExplicit
	b.ActorID = identity.ActorID(b.UserID)
	fp := [32]byte{7}
	state := &CapabilityPlan{CapabilityID: "original-state", Purpose: "identity.oauth.callback", ReplayDigest: [32]byte{8}, ReplayKeyVersion: 1, ProofFingerprint: [32]byte{9}, ExpiresAt: time.Unix(1800000000, 0).UTC(), MaxUses: 1}
	grant := *state
	grant.CapabilityID, grant.Purpose, grant.ReplayDigest, grant.ProofFingerprint = "final-link", "identity.account.link-token", [32]byte{3}, [32]byte{4}
	p := CommandPlan{AccountLinkState: state, Capability: &grant,
		Contributors: []ContributorDescriptor{{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}, {Owner: "audit/postgres", ContractID: "audit.records", Version: 1}, {Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}, {Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}, accountLinkCounterDescriptor(), accountLinkOwnerDescriptor()},
		Audits:       []AuditPlan{{EventType: "identity.account.link", SchemaVersion: 1, BindingDigest: [32]byte{1}, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 4096, MaxAggregateBytes: 4096, Required: true}},
		Lifecycle:    &LifecyclePlan{EventType: "social_provider.linked.v1", AfterVersion: 1}, CommandCounters: &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{5}}}
	for _, beforeExchange := range []bool{false, true} {
		if beforeExchange {
			p.Capability = nil
		}
		seed, err := encodeAccountLinkStatePlan(b, fp, p)
		if err != nil {
			f.Fatal("invalid decoder corpus seed", err)
		}
		f.Add(seed)
	}
	p.Audits = oauthAccountLinkAuditPlans(p.Audits[0])
	seed, err := encodeAccountLinkStatePlan(b, fp, p)
	if err != nil {
		f.Fatal("invalid composed OAuth audit decoder corpus seed", err)
	}
	f.Add(seed)
	f.Add([]byte{0xa6})
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := decodeAccountLinkStatePlan(b, fp, raw)
		if err != nil {
			return
		}
		canonical, err := encodeAccountLinkStatePlan(b, fp, decoded)
		if err != nil || !bytes.Equal(canonical, raw) || decoded.AccountLinkState == nil || decoded.AccountLinkState.Purpose != "identity.oauth.callback" || len(decoded.Contributors) != 6 {
			t.Fatal("noncanonical or incomplete original-state input accepted")
		}
	})
}
