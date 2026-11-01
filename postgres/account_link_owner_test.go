package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

type accountLinkCounterProbe struct {
	commandCounterProbe
	deny                 bool
	evidenceTTL          time.Duration
	expiresAt, checkedAt time.Time
}

func (p *accountLinkCounterProbe) ReserveCommandCounters(ctx context.Context, h CommandCounterWork) (CommandCounterDisposition, error) {
	if _, err := h.Binding(p); err != nil {
		return 0, err
	}
	if p.deny {
		return CommandCounterDenied, nil
	}
	if p.evidenceTTL > 0 {
		now, err := h.DatabaseTime(ctx)
		if err != nil {
			return 0, err
		}
		p.expiresAt = now.Add(p.evidenceTTL)
	}
	return CommandCounterAllowed, nil
}

func (p *accountLinkCounterProbe) CheckCommandCounters(ctx context.Context, h CommandCounterAdmissionWork) error {
	_, err := h.Binding(p)
	if err == nil && p.evidenceTTL > 0 {
		p.checkedAt, err = h.DatabaseTime(ctx)
		if err == nil && !p.checkedAt.Before(p.expiresAt) {
			return identity.ForbiddenError{}
		}
	}
	return err
}

type accountLinkOwnerProbe struct{ check func(AccountLinkWork) error }

type accountLinkDomainProbe struct{ registryContributor }

func (*accountLinkDomainProbe) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryNotCommitted, nil
}

type accountLinkAuditProbe struct{ planAuditContributor }

func (*accountLinkAuditProbe) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryNotCommitted, nil
}

type accountLinkLifecycleProbe struct{ planLifecycleContributor }

func (*accountLinkLifecycleProbe) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryNotCommitted, nil
}

func (*accountLinkOwnerProbe) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.account-link", Version: 1}
}
func (*accountLinkOwnerProbe) PrepareAccountLink(context.Context, identity.Command) (identity.Command, CommandCounterPlan, CapabilityPlan, error) {
	return identity.Command{}, CommandCounterPlan{}, CapabilityPlan{}, invalidPlan()
}
func (*accountLinkOwnerProbe) ValidateAccountLink(identity.Command, CommandPlan) error { return nil }
func (p *accountLinkOwnerProbe) CheckAccountLink(_ context.Context, h AccountLinkWork) error {
	if p.check != nil {
		return p.check(h)
	}
	_, _, err := h.Command(p)
	return err
}
func (p *accountLinkOwnerProbe) PersistAccountLink(_ context.Context, h AccountLinkWork) error {
	_, _, err := h.Command(p)
	return err
}
func (p *accountLinkOwnerProbe) FinalizeAccountLink(_ context.Context, h AccountLinkWork) error {
	_, _, err := h.Command(p)
	return err
}
func (*accountLinkOwnerProbe) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryNotCommitted, nil
}

func accountLinkOwnerPlanFixture(t *testing.T) (*Coordinator, identity.Command, CommandPlan) {
	t.Helper()
	c, _, plan := coordinatorFixture(t)
	original := recordLink(t, identity.AccountLinkExplicit, nil, nil, "proof-key")
	command, err := identity.NewAccountLinkCounterCommand(original, identity.AccountLinkCounterContext{Network: "192.0.2.15", PreparedAt: time.Unix(1000, 0).UTC(), KeyVersions: []uint32{7}})
	if err != nil {
		t.Fatal(err)
	}
	spec, _, _ := command.AccountLinkCounterCommand()
	capability := &capabilityExecutionProbe{}
	owner := &accountLinkOwnerProbe{}
	entries := []Contributor{&accountLinkDomainProbe{registryContributor{c.registry.state.entries[0].descriptor}}, &accountLinkAuditProbe{planAuditContributor{registryContributor{c.registry.state.entries[1].descriptor}}}, &accountLinkLifecycleProbe{planLifecycleContributor{registryContributor{c.registry.state.entries[2].descriptor}}}, capability, &accountLinkCounterProbe{}, owner}
	c.registry, err = NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	plan.Contributors = c.registry.Descriptors()
	proof := spec.Proof.Payload()
	plan.Capability = &CapabilityPlan{CapabilityID: proof.ID, Purpose: "identity.account.link-token", ReplayDigest: [32]byte{3}, ReplayKeyVersion: 1, ProofFingerprint: spec.Proof.EnvelopeDigest(), ExpiresAt: proof.ExpiresAt, MaxUses: 1}
	plan.CommandCounters = &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{4}}
	plan.Lifecycle = &LifecyclePlan{EventType: "social_provider.linked.v1", AfterVersion: 1}
	record, err := securityMutationAudit(context.Background(), spec.Binding, 0, 1, time.Unix(1000, 0).UTC(), "committed", "identity.account.link", "account", spec.Binding.RecordID, "standard", false)
	if err != nil {
		t.Fatal(err)
	}
	plan.Audits[0].EventType = "identity.account.link"
	plan.Audits[0].BindingDigest, err = AuditBindingDigest(spec.Binding, record)
	if err != nil {
		t.Fatal(err)
	}
	return c, command, plan
}

func TestAccountLinkOwnerClosedPlanRoundTripAndSubstitution(t *testing.T) {
	c, command, plan := accountLinkOwnerPlanFixture(t)
	spec, _, _ := command.AccountLinkCounterCommand()
	prepared, err := c.PrepareCommandPlan(spec.Binding, command, plan)
	if err != nil {
		t.Fatal("complete canonical link profile cannot prepare", err)
	}
	q, _, admitted, err := c.prepare(spec.Binding, command, prepared)
	if err != nil {
		t.Fatal(err)
	}
	fp := claimFingerprint(c.keys.retained[1], q.canonical)
	wire, err := encodeKernelPlan(spec.Binding, fp, prepared)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeKernelPlan(spec.Binding, fp, wire)
	if err != nil || !reflect.DeepEqual(decoded, prepared) || !reflect.DeepEqual(admitted.snapshot(), prepared) {
		t.Fatal("closed link plan lost mandatory participants", err)
	}
	for _, mutate := range []func(*CommandPlan){
		func(p *CommandPlan) { p.CommandCounters = nil },
		func(p *CommandPlan) { p.Capability = nil },
		func(p *CommandPlan) { p.Capability.ProofFingerprint[0] ^= 1 },
		func(p *CommandPlan) { p.Capability.ExpiresAt = p.Capability.ExpiresAt.Add(time.Second) },
		func(p *CommandPlan) { p.Lifecycle.AfterVersion++ },
		func(p *CommandPlan) { p.Contributors = p.Contributors[:5] },
		func(p *CommandPlan) { p.Feature = &FeatureRegistration{} },
	} {
		candidate := prepared
		capability, lifecycle := *prepared.Capability, *prepared.Lifecycle
		candidate.Capability, candidate.Lifecycle = &capability, &lifecycle
		candidate.Contributors = append([]ContributorDescriptor(nil), prepared.Contributors...)
		mutate(&candidate)
		if _, err := c.PrepareCommandPlan(spec.Binding, command, candidate); err == nil {
			t.Fatal("incomplete or substituted link profile admitted")
		}
	}
	bad := bytes.Clone(wire)
	bad[len(bad)-1] ^= 1
	if _, err := decodeKernelPlan(spec.Binding, fp, bad); err == nil {
		t.Fatal("changed retained plan accepted")
	}
	for i := range wire {
		if _, err := decodeKernelPlan(spec.Binding, fp, wire[:i]); err == nil {
			t.Fatal("truncated link plan accepted", i)
		}
	}
}

func accountLinkInvocationFixture(t *testing.T) (*Coordinator, Work, identity.Command, *accountLinkOwnerProbe) {
	t.Helper()
	c, command, plan := accountLinkOwnerPlanFixture(t)
	spec, _, _ := command.AccountLinkCounterCommand()
	q, _, admitted, err := c.prepare(spec.Binding, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	w := Work{state: &workState{ctx: ctx, cancel: cancel, binding: spec.Binding, generation: 1, registry: c.registry.state}}
	w.state.execution = &domainExecution{coordinator: c, reservation: &reservationState{coordinator: c, plan: admitted, request: q}}
	return c, w, command, admitted.accountLink.contributor.(*accountLinkOwnerProbe)
}

func TestAccountLinkOwnerInvocationCustody(t *testing.T) {
	c, w, command, owner := accountLinkInvocationFixture(t)
	var retained AccountLinkWork
	owner.check = func(h AccountLinkWork) error {
		retained = h
		spec, final, err := h.Command(owner)
		if err != nil || final || spec.Change.Method == nil {
			t.Fatal("wrong initial custody", err)
		}
		spec.Change.Method.Credential.ID = "changed"
		again, _, err := h.Command(owner)
		if err != nil || again.Change.Method.Credential.ID == "changed" {
			t.Fatal("native callback mutated frozen method", err)
		}
		if fmt.Sprintf("%#v", h) != "postgres.AccountLinkWork(redacted)" {
			t.Fatal("handle exposed custody")
		}
		if _, err := json.Marshal(h); err == nil {
			t.Fatal("handle exported custody")
		}
		return nil
	}
	if err := c.runAccountLinkPhase(w.state.ctx, w, command, accountLinkCheck); err != nil {
		t.Fatal(err)
	}
	if _, _, err := retained.Command(owner); err == nil {
		t.Fatal("retained invocation remained live")
	}
	if err := c.runAccountLinkPhase(w.state.ctx, w, command, accountLinkCheck); err == nil || w.usable() == nil {
		t.Fatal("initial admission ran twice")
	}
}

func TestAccountLinkOwnerIgnoredDenialAndPanicPoisonWork(t *testing.T) {
	for _, mode := range []string{"foreign", "read-only", "panic", "error", "final-before-apply", "changed-command"} {
		t.Run(mode, func(t *testing.T) {
			c, w, command, owner := accountLinkInvocationFixture(t)
			owner.check = func(h AccountLinkWork) error {
				switch mode {
				case "foreign":
					_, _, _ = h.Command(&accountLinkOwnerProbe{})
				case "read-only":
					_, _ = h.Exec(w.state.ctx, "SELECT 1")
				case "panic":
					panic("private diagnostic")
				case "error":
					return fmt.Errorf("private diagnostic")
				}
				return nil
			}
			phase := accountLinkCheck
			if mode == "final-before-apply" {
				phase = accountLinkFinalCheck
			}
			if mode == "changed-command" {
				spec, counter, _ := command.AccountLinkCounterCommand()
				counter.Network = "192.0.2.200"
				base, _ := identity.NewAccountLinkCommand(spec)
				command, _ = identity.NewAccountLinkCounterCommand(base, counter)
			}
			if err := c.runAccountLinkPhase(w.state.ctx, w, command, phase); err == nil || w.usable() == nil {
				t.Fatal("denial ignored")
			}
		})
	}
}

func TestAccountLinkOwnerAuditTargetsAccount(t *testing.T) {
	_, command, _ := accountLinkOwnerPlanFixture(t)
	spec, _, _ := command.AccountLinkCounterCommand()
	record, err := kernelMutationAudit(context.Background(), spec.Binding, 0, time.Unix(1000, 0).UTC(), "committed")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AuditBindingDigest(spec.Binding, record); err != nil {
		t.Fatal("canonical link audit cannot bind its account target", err)
	}
}

func TestAccountLinkOwnerRejectsRegistrationWithoutCompletePhases(t *testing.T) {
	for missing := 0; missing < 6; missing++ {
		c, command, plan := accountLinkOwnerPlanFixture(t)
		entries := make([]Contributor, 6)
		for i := range entries {
			entries[i] = c.registry.state.entries[i].contributor
		}
		entries[missing] = &registryContributor{c.registry.state.entries[missing].descriptor}
		registry, err := NewContributorRegistry(entries)
		if err != nil {
			t.Fatal(err)
		}
		c.registry = registry
		spec, _, _ := command.AccountLinkCounterCommand()
		if _, err := c.PrepareCommandPlan(spec.Binding, command, plan); err == nil {
			t.Fatal("name-only owner enabled protected link", missing)
		}
	}
}

func TestAccountLinkOwnerProofHasExclusivePrimaryBounds(t *testing.T) {
	command := recordLink(t, identity.AccountLinkExplicit, nil, nil, "proof-key")
	spec, _ := command.LinkAccount()
	for _, tc := range []struct {
		now   time.Time
		valid bool
	}{
		{time.Time{}, false}, {time.Unix(899, 0), false}, {time.Unix(900, 0), true},
		{time.Unix(1099, 999999000), true}, {time.Unix(1100, 0), false}, {time.Unix(1200, 0), false},
	} {
		if got := accountLinkProofCurrent(spec, tc.now); got != tc.valid {
			t.Fatal("proof time bounds changed", got, tc.valid)
		}
	}
}

func FuzzAccountLinkOwnerPlanDecoder(f *testing.F) {
	b := recordBinding("identity.account.link-token", "identity-account", "account-a")
	b.LinkMode = identity.AccountLinkExplicit
	fingerprint := [32]byte{1}
	p, err := decodeKernelPlan(b, fingerprint, queryFrozenPlan(f, b))
	if err != nil {
		f.Fatal(err)
	}
	p.Lifecycle = &LifecyclePlan{EventType: kernelLifecycleEvent(b.OperationID), AfterVersion: 1}
	p.Capability = &CapabilityPlan{CapabilityID: "proof-a", Purpose: capability.Purpose(b.OperationID), ReplayDigest: [32]byte{2}, ReplayKeyVersion: 1, ProofFingerprint: [32]byte{3}, ExpiresAt: time.Unix(1100, 0).UTC(), MaxUses: 1}
	p.CommandCounters = &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{4}}
	p.Contributors = append(p.Contributors,
		ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1},
		ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1},
		accountLinkCounterDescriptor(), accountLinkOwnerDescriptor())
	wire, err := encodeKernelPlan(b, fingerprint, p)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte(nil))
	f.Add(wire[:len(wire)/2])
	f.Add(bytes.Repeat([]byte{0xa5}, 65537))
	f.Fuzz(func(t *testing.T, input []byte) {
		decoded, err := decodeKernelPlan(b, fingerprint, input)
		if err != nil {
			if !reflect.DeepEqual(decoded, CommandPlan{}) {
				t.Fatal("invalid bytes leaked partial plan")
			}
			return
		}
		canonical, err := encodeKernelPlan(b, fingerprint, decoded)
		if err != nil || !bytes.Equal(canonical, input) || decoded.Digest != sha256.Sum256(input) {
			t.Fatal("accepted bytes changed their declaration")
		}
	})
}
