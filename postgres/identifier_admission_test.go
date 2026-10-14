package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

// Bounded plan: exact enlisted session owner, immutable complete command and
// phase, retained/wrong participant denial, ignored guard errors, panic/cancel,
// and unchanged disabled public Begin. Real owner SQL remains separately tested.
type identifierAdmissionProbe struct {
	retained IdentifierAdmissionWork
	inspect  func(IdentifierAdmissionWork) error
}

func (*identifierAdmissionProbe) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session.store", Version: 1}
}
func (p *identifierAdmissionProbe) CheckIdentifier(ctx context.Context, w IdentifierAdmissionWork) error {
	p.retained = w
	if p.inspect != nil {
		return p.inspect(w)
	}
	_, _, err := w.Command(p)
	return err
}

func identifierAdmissionFixture(t *testing.T, p *identifierAdmissionProbe) (*Coordinator, Work, identity.Command) {
	t.Helper()
	cap := &capabilityExecutionProbe{}
	c, command, plan := reservationPlanFixture(t, cap)
	entries := make([]Contributor, 0, len(c.registry.state.entries)+1)
	for _, e := range c.registry.state.entries {
		entries = append(entries, e.contributor)
	}
	entries = append(entries, p)
	var err error
	c.registry, err = NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := p.Descriptor()
	plan.IdentifierAdmission = &descriptor
	spec, _ := command.ChangeIdentifier()
	prepared, err := c.PrepareCommandPlan(spec.Binding, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	request, _, admitted, err := c.prepare(spec.Binding, command, prepared)
	if err != nil {
		t.Fatal(err)
	}
	_, w := capabilityDomainFixture(t, cap)
	w.state.registry = c.registry.state
	w.state.execution = &domainExecution{coordinator: c, reservation: &reservationState{coordinator: c, plan: admitted, request: request}}
	return c, w, command
}

func TestIdentifierAdmissionInvocationOwnsExactCommandAndLifetime(t *testing.T) {
	for _, final := range []bool{false, true} {
		p := &identifierAdmissionProbe{}
		c, w, command := identifierAdmissionFixture(t, p)
		spec, _ := command.ChangeIdentifier()
		if final {
			if err := c.runIdentifierAdmission(w.state.ctx, w, command, false); err != nil {
				t.Fatal(err)
			}
			w.state.identifier = identifierOwnedAdmissionResult(t, command)
		}
		p.inspect = func(handle IdentifierAdmissionWork) error {
			got, phase, err := handle.Command(p)
			if err != nil || phase != final || got.Binding != spec.Binding || got.Change != spec.Change || got.SessionID != spec.SessionID || got.SessionVersion != spec.SessionVersion || !reflect.DeepEqual(got.Proof, spec.Proof) {
				t.Fatal("command or phase substituted", err)
			}
			return nil
		}
		if err := c.runIdentifierAdmission(w.state.ctx, w, command, final); err != nil {
			t.Fatal(err)
		}
		if _, _, err := p.retained.Command(p); err == nil {
			t.Fatal("retained admission authority")
		}
		if _, err := p.retained.Query(context.Background(), "SELECT 1"); err == nil {
			t.Fatal("retained cursor authority")
		}
		if w.usable() != nil {
			t.Fatal("successful phase poisoned original Work")
		}
		r := Reservation{state: w.state.execution.reservation}
		if _, err := c.Begin(context.Background(), r); err == nil || r.state.started.Load() {
			t.Fatal("incomplete public execution activated")
		}
	}
}

func TestIdentifierAdmissionDenialCannotBeIgnored(t *testing.T) {
	for name, check := range map[string]func(*identifierAdmissionProbe, IdentifierAdmissionWork){
		"foreign": func(_ *identifierAdmissionProbe, h IdentifierAdmissionWork) {
			_, _, _ = h.Command(&identifierAdmissionProbe{})
		},
		"nil": func(_ *identifierAdmissionProbe, h IdentifierAdmissionWork) { _, _, _ = h.Command(nil) },
		"bad credential": func(p *identifierAdmissionProbe, h IdentifierAdmissionWork) {
			_, _ = h.RequireActiveCredential(context.Background(), p, CredentialAdmission{})
		},
		"bad directory": func(p *identifierAdmissionProbe, h IdentifierAdmissionWork) {
			_ = h.RequireActiveDirectoryAuthority(context.Background(), p, DirectoryAuthorityAdmission{})
		},
		"bad authorization": func(p *identifierAdmissionProbe, h IdentifierAdmissionWork) {
			_ = h.RequireActiveUserAuthorization(context.Background(), p, UserAuthorizationAdmission{})
		},
		"nil query context": func(_ *identifierAdmissionProbe, h IdentifierAdmissionWork) { _, _ = h.Query(nil, "SELECT 1") },
		"active cursor": func(_ *identifierAdmissionProbe, h IdentifierAdmissionWork) {
			// Exercise the pre-SQL guard directly; clearing the fixture cursor
			// models cleanup and must not erase an already denied invocation.
			h.state.work.state.rows = &WorkRows{}
			_, _ = h.Query(context.Background(), "SELECT 1")
			h.state.work.state.rows = nil
		},
		"active cursor clock": func(_ *identifierAdmissionProbe, h IdentifierAdmissionWork) {
			h.state.work.state.rows = &WorkRows{}
			_, _ = h.DatabaseTime(context.Background())
			h.state.work.state.rows = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := &identifierAdmissionProbe{}
			c, w, cmd := identifierAdmissionFixture(t, p)
			p.inspect = func(h IdentifierAdmissionWork) error { check(p, h); return nil }
			if err := c.runIdentifierAdmission(w.state.ctx, w, cmd, false); err == nil || w.usable() == nil || w.state.sqlStarted {
				t.Fatal("ignored denial accepted", err)
			}
		})
	}
}

func TestIdentifierAdmissionFailureAndCommandSubstitution(t *testing.T) {
	for name, inspect := range map[string]func(IdentifierAdmissionWork) error{
		"deny":  func(IdentifierAdmissionWork) error { return identity.ForbiddenError{} },
		"panic": func(IdentifierAdmissionWork) error { panic("private diagnostic") },
	} {
		t.Run(name, func(t *testing.T) {
			p := &identifierAdmissionProbe{inspect: inspect}
			c, w, cmd := identifierAdmissionFixture(t, p)
			if err := c.runIdentifierAdmission(w.state.ctx, w, cmd, false); err == nil || w.usable() == nil {
				t.Fatal("failure became success")
			}
			if _, _, err := p.retained.Command(p); err == nil {
				t.Fatal("failed phase retained authority")
			}
		})
	}
	p := &identifierAdmissionProbe{}
	c, w, cmd := identifierAdmissionFixture(t, p)
	spec, _ := cmd.ChangeIdentifier()
	spec.Binding.CorrelationID = "other"
	changed, err := identity.NewIdentifierCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.runIdentifierAdmission(w.state.ctx, w, changed, false); err == nil || p.retained.state != nil {
		t.Fatal("substituted command invoked owner")
	}
	p = &identifierAdmissionProbe{}
	c, w, cmd = identifierAdmissionFixture(t, p)
	cancelled, cancel := context.WithCancel(w.state.ctx)
	cancel()
	var ce identity.CancelledError
	if err = c.runIdentifierAdmission(cancelled, w, cmd, false); !errors.As(err, &ce) || p.retained.state != nil {
		t.Fatal("cancelled phase invoked owner", err)
	}
	if _, _, err := (IdentifierAdmissionWork{}).Command(nil); err == nil {
		t.Fatal("zero handle admitted")
	}
	if got := fmt.Sprintf("%#v", p.retained); got != "postgres.IdentifierAdmissionWork(redacted)" {
		t.Fatal("handle disclosed", got)
	}
	if data, err := json.Marshal(p.retained); err == nil || len(data) != 0 {
		t.Fatal("handle serialized")
	}
}

func TestIdentifierAdmissionPlanFreezesReadOnlyRole(t *testing.T) {
	p := &identifierAdmissionProbe{}
	c, w, cmd := identifierAdmissionFixture(t, p)
	plan := w.state.execution.reservation.plan
	snapshot := plan.snapshot()
	if snapshot.IdentifierAdmission == nil || *snapshot.IdentifierAdmission != p.Descriptor() {
		t.Fatal("read-only role omitted")
	}
	for _, entry := range plan.contributors {
		if entry.descriptor == p.Descriptor() {
			t.Fatal("checker became recovery effect owner")
		}
	}
	wire, err := encodeKernelPlan(plan.binding, plan.fingerprint, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeKernelPlan(plan.binding, plan.fingerprint, wire)
	if err != nil || decoded.Digest != plan.digest || decoded.IdentifierAdmission == nil || *decoded.IdentifierAdmission != p.Descriptor() {
		t.Fatal("journal role roundtrip", err)
	}
	for i := 0; i < len(wire); i++ {
		if _, err := decodeKernelPlan(plan.binding, plan.fingerprint, wire[:i]); err == nil {
			t.Fatal("truncated plan accepted", i)
		}
	}
	*snapshot.IdentifierAdmission = ContributorDescriptor{}
	if _, err := KernelPlanDigest(plan.binding, plan.fingerprint, snapshot); err == nil {
		t.Fatal("invalid role accepted")
	}
	if err := c.runIdentifierAdmission(w.state.ctx, w, cmd, false); err != nil {
		t.Fatal("caller mutation changed frozen role", err)
	}
	base := plan.snapshot()
	base.IdentifierAdmission = nil
	old, err := encodeKernelPlan(plan.binding, plan.fingerprint, base)
	if err != nil {
		t.Fatal(err)
	}
	oldPlan, err := decodeKernelPlan(plan.binding, plan.fingerprint, old)
	if err != nil || oldPlan.IdentifierAdmission != nil {
		t.Fatal("historical role-free decode", err)
	}
	if _, err := c.registry.admitKernelPlan(plan.binding, plan.fingerprint, decoded); err != nil {
		t.Fatal(err)
	}
}

func TestIdentifierAdmissionCannotDisappearDuringFeaturePreparation(t *testing.T) {
	c, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	d := identifierAdmissionDescriptor()
	plan.IdentifierAdmission = &d
	if _, err := c.PrepareCommandPlan(spec.Binding, command, plan); err == nil {
		t.Fatal("forbidden admission role silently omitted")
	}
}
