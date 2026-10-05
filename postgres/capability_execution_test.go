package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type capabilityExecutionProbe struct {
	capabilityReservationProbe
	apply      CapabilityApplyWork
	finalize   CapabilityFinalizeWork
	failure    error
	panicPhase bool
	inspect    func(*capabilityExecutionState)
}

func (*capabilityExecutionProbe) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}
func (*capabilityExecutionProbe) ReleaseCapability(context.Context, CapabilityReleaseWork) error {
	return nil
}
func (p *capabilityExecutionProbe) ApplyCapability(_ context.Context, w CapabilityApplyWork) error {
	p.apply = w
	if p.inspect != nil {
		p.inspect(w.state)
	}
	if p.panicPhase {
		panic("private material")
	}
	if _, err := w.Binding(p); err != nil {
		return err
	}
	return p.failure
}
func (p *capabilityExecutionProbe) FinalizeCapability(_ context.Context, w CapabilityFinalizeWork) error {
	p.finalize = w
	if p.inspect != nil {
		p.inspect(w.state)
	}
	if p.panicPhase {
		panic("private material")
	}
	if _, err := w.Binding(p); err != nil {
		return err
	}
	return p.failure
}

func capabilityDomainFixture(t *testing.T, p *capabilityExecutionProbe) (*Coordinator, Work) {
	t.Helper()
	c, command, plan := reservationPlanFixture(t, p)
	spec, _ := command.ChangeIdentifier()
	prepared, err := c.PrepareCommandPlan(spec.Binding, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	_, _, admitted, err := c.prepare(spec.Binding, command, prepared)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	w := Work{state: &workState{ctx: ctx, cancel: cancel, binding: spec.Binding, generation: 3, registry: c.registry.state}}
	w.state.execution = &domainExecution{coordinator: c, reservation: &reservationState{coordinator: c, plan: admitted}}
	return c, w
}

func TestCapabilityDomainInvocationCustody(t *testing.T) {
	for _, finalize := range []bool{false, true} {
		p := &capabilityExecutionProbe{}
		c, w := capabilityDomainFixture(t, p)
		if err := c.runCapabilityExecution(w.state.ctx, w, finalize); err != nil {
			t.Fatal(err)
		}
		if finalize {
			if _, err := p.finalize.Binding(p); err == nil {
				t.Fatal("retained finalization authority")
			}
		} else if _, err := p.apply.Binding(p); err == nil {
			t.Fatal("retained apply authority")
		}
	}
}

func TestCapabilityDomainFailuresPoisonWork(t *testing.T) {
	for _, finalize := range []bool{false, true} {
		for _, panics := range []bool{false, true} {
			p := &capabilityExecutionProbe{failure: identity.ConflictError{}, panicPhase: panics}
			c, w := capabilityDomainFixture(t, p)
			if err := c.runCapabilityExecution(w.state.ctx, w, finalize); err == nil || w.usable() == nil {
				t.Fatal("failed invocation did not poison work")
			}
		}
	}
}

func TestCapabilityDomainAuthorityCannotBeConstructed(t *testing.T) {
	p := &capabilityExecutionProbe{}
	apply, finalize := CapabilityApplyWork{}, CapabilityFinalizeWork{}
	if _, err := apply.Binding(p); err == nil {
		t.Fatal("zero apply binding")
	}
	if _, err := finalize.Binding(p); err == nil {
		t.Fatal("zero finalize binding")
	}
	if _, err := apply.Exec(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero apply execution")
	}
	if _, err := finalize.Exec(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero finalize execution")
	}
	for _, value := range []any{apply, finalize} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("serialized authority")
		}
		if got := fmt.Sprintf("%+v", value); got != "postgres.CapabilityApplyWork(redacted)" && got != "postgres.CapabilityFinalizeWork(redacted)" {
			t.Fatal("unredacted authority")
		}
	}
}

func TestCapabilityDomainExactIdentityAndPhase(t *testing.T) {
	for _, finalize := range []bool{false, true} {
		p := &capabilityExecutionProbe{}
		c, w := capabilityDomainFixture(t, p)
		p.inspect = func(s *capabilityExecutionState) {
			binding, err := s.binding(p, finalize)
			if err != nil || binding.Command != w.state.binding || binding.Generation != 3 || binding.PreviousGeneration != 0 || binding.Plan != *s.reservation.plan.capability {
				t.Fatal("binding substituted", err)
			}
			binding.Plan.CapabilityID = "foreign"
			if s.reservation.plan.capability.CapabilityID == "foreign" {
				t.Fatal("binding aliases owner")
			}
			if _, err := s.binding(&capabilityExecutionProbe{}, finalize); err == nil {
				t.Fatal("foreign instance admitted")
			}
			if _, err := s.binding(p, !finalize); err == nil {
				t.Fatal("wrong phase admitted")
			}
			s.reservation.previousGeneration = 2
			if _, err := s.binding(p, finalize); err == nil {
				t.Fatal("takeover authority admitted")
			}
			s.reservation.previousGeneration = 0
			original := w.state.registry
			w.state.registry = &contributorRegistryState{}
			if _, err := s.binding(p, finalize); err == nil {
				t.Fatal("foreign registry admitted")
			}
			w.state.registry = original
		}
		if err := c.runCapabilityExecution(w.state.ctx, w, finalize); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCapabilityDomainCancelledInvocation(t *testing.T) {
	p := &capabilityExecutionProbe{}
	c, w := capabilityDomainFixture(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.runCapabilityExecution(ctx, w, false); err == nil || w.usable() == nil || p.apply.state != nil {
		t.Fatal("cancelled caller invoked participant")
	}
}

func TestCapabilityDomainCancellationDuringInvocation(t *testing.T) {
	for _, finalize := range []bool{false, true} {
		p := &capabilityExecutionProbe{}
		c, w := capabilityDomainFixture(t, p)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		p.inspect = func(*capabilityExecutionState) { cancel() }
		var cancelled identity.CancelledError
		if err := c.runCapabilityExecution(ctx, w, finalize); !errors.As(err, &cancelled) || w.usable() == nil {
			t.Fatal("mid-invocation cancellation ignored")
		}
		if _, err := p.apply.Binding(p); err == nil {
			t.Fatal("retained apply after cancellation")
		}
		if _, err := p.finalize.Binding(p); err == nil {
			t.Fatal("retained finalization after cancellation")
		}
	}
}
