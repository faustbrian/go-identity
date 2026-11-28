package impersonation_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/impersonation"
)

func TestActivateApprovedGrantPreservesBoundLineage(t *testing.T) {
	pending, approvalInput := fixture(t)
	approved, approval, err := impersonation.Approve(pending, approvalInput)
	if err != nil {
		t.Fatal(err)
	}
	at := approval.At().Add(time.Minute)
	parentExpiresAt := at.Add(5 * time.Minute)
	active, session, err := impersonation.Activate(approved, impersonation.ActivationInput{
		GrantID: approved.ID(), ExpectedVersion: 2, Approval: approval,
		Actor: approved.Request().Actor(), CurrentTarget: approved.Request().Target(),
		CurrentPolicy: approved.Request().Policy(), ParentSessionID: "ordinary-session:actor",
		ParentSessionVersion: 9, ParentExpiresAt: parentExpiresAt, At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	if active.Status() != impersonation.StatusActive || active.Version() != 3 {
		t.Fatal("activation did not advance the exact approved grant")
	}
	if approved.Status() != impersonation.StatusApproved || approved.Version() != 2 || !active.ExpiresAt().Equal(approved.ExpiresAt()) {
		t.Fatal("activation mutated its input or changed the approval deadline")
	}
	b := session.Bindings()
	if b.GrantID != approved.ID() || b.GrantVersion != 3 || b.TenantID != "tenant" || b.ActorID != "actor" || b.TargetID != "target" || b.TargetVersion != 7 || b.ParentSessionID != "ordinary-session:actor" || b.ParentSessionVersion != 9 {
		t.Fatal("active session lost its immutable grant, identity or parent lineage")
	}
	if b.Policy != approved.Request().Policy() || !b.StartedAt.Equal(at) || !b.ExpiresAt.Equal(parentExpiresAt) {
		t.Fatal("active session lost policy or exceeded the parent's lifetime")
	}
	permissions := b.Scope.Permissions()
	if len(permissions) != 2 || permissions[0] != "address:read" || permissions[1] != "profile:read" {
		t.Fatal("active scope was not derived from the approved intent")
	}
	permissions[0] = "admin:*"
	if session.Bindings().Scope.Permissions()[0] != "address:read" {
		t.Fatal("active scope aliases caller-owned storage")
	}
}

func activationFixture(t *testing.T) (impersonation.Grant, impersonation.ActivationInput) {
	t.Helper()
	pending, approvalInput := fixture(t)
	approved, approval, err := impersonation.Approve(pending, approvalInput)
	if err != nil {
		t.Fatal(err)
	}
	at := approval.At().Add(time.Minute)
	return approved, impersonation.ActivationInput{
		GrantID: approved.ID(), ExpectedVersion: 2, Approval: approval,
		Actor: approved.Request().Actor(), CurrentTarget: approved.Request().Target(),
		CurrentPolicy: approved.Request().Policy(), ParentSessionID: "ordinary-session:actor",
		ParentSessionVersion: 9, ParentExpiresAt: at.Add(time.Hour), At: at,
	}
}

func TestActivateRejectsUnboundOrStaleIntent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *impersonation.Grant, *impersonation.ActivationInput)
		want   error
	}{
		{"zero grant", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			*g = impersonation.Grant{}
		}, impersonation.ErrConflict},
		{"pending", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) { *g, _ = fixture(t) }, impersonation.ErrConflict},
		{"wrong grant", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.GrantID = "AgICAgICAgICAgICAgICAg"
		}, impersonation.ErrConflict},
		{"old version", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) { in.ExpectedVersion = 1 }, impersonation.ErrConflict},
		{"future version", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) { in.ExpectedVersion = 3 }, impersonation.ErrConflict},
		{"missing approval", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.Approval = impersonation.Approval{}
		}, impersonation.ErrConflict},
		{"foreign approval", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			pending, ai := fixture(t)
			foreign, err := impersonation.NewPendingGrant("AgICAgICAgICAgICAgICAg", pending.Request(), pending.RequestedAt())
			if err != nil {
				t.Fatal(err)
			}
			ai.GrantID = foreign.ID()
			_, in.Approval, err = impersonation.Approve(foreign, ai)
			if err != nil {
				t.Fatal(err)
			}
		}, impersonation.ErrConflict},
		{"different approved epoch", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			pending, ai := fixture(t)
			ai.At = ai.At.Add(time.Second)
			var err error
			_, in.Approval, err = impersonation.Approve(pending, ai)
			if err != nil {
				t.Fatal(err)
			}
		}, impersonation.ErrConflict},
		{"different approver", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			pending, ai := fixture(t)
			ai.Approver, _ = impersonation.NewActor("tenant", "other-approver")
			var err error
			_, in.Approval, err = impersonation.Approve(pending, ai)
			if err != nil {
				t.Fatal(err)
			}
		}, impersonation.ErrConflict},
		{"different approved reason", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			pending, ai := fixture(t)
			ai.Reason, _ = impersonation.NewReason("a different decision")
			var err error
			_, in.Approval, err = impersonation.Approve(pending, ai)
			if err != nil {
				t.Fatal(err)
			}
		}, impersonation.ErrConflict},
		{"different request digest", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			pending, ai := fixture(t)
			ri := pending.Request().Input()
			ri.Duration = time.Minute
			request, err := impersonation.NewRequest(ri)
			if err != nil {
				t.Fatal(err)
			}
			other, err := impersonation.NewPendingGrant(pending.ID(), request, pending.RequestedAt())
			if err != nil {
				t.Fatal(err)
			}
			ai.Request = request
			_, in.Approval, err = impersonation.Approve(other, ai)
			if err != nil {
				t.Fatal(err)
			}
		}, impersonation.ErrConflict},
		{"wrong actor", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.Actor, _ = impersonation.NewActor("tenant", "other")
		}, impersonation.ErrConflict},
		{"approver as actor", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.Actor = in.Approval.Approver()
		}, impersonation.ErrConflict},
		{"target as actor", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.Actor, _ = impersonation.NewActor("tenant", "target")
		}, impersonation.ErrConflict},
		{"foreign actor tenant", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.Actor, _ = impersonation.NewActor("other-tenant", "actor")
		}, impersonation.ErrConflict},
		{"wrong target", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.CurrentTarget, _ = impersonation.NewTarget("tenant", "other", 7)
		}, impersonation.ErrConflict},
		{"changed target version", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.CurrentTarget, _ = impersonation.NewTarget("tenant", "target", 8)
		}, impersonation.ErrConflict},
		{"changed target tenant", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.CurrentTarget, _ = impersonation.NewTarget("other", "target", 7)
		}, impersonation.ErrConflict},
		{"wrong policy", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.CurrentPolicy, _ = impersonation.NewPolicy("other", 3)
		}, impersonation.ErrConflict},
		{"changed policy version", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.CurrentPolicy, _ = impersonation.NewPolicy("support", 4)
		}, impersonation.ErrConflict},
		{"missing actor", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.Actor = impersonation.Actor{}
		}, impersonation.ErrInvalidInput},
		{"missing parent", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) { in.ParentSessionID = "" }, impersonation.ErrInvalidInput},
		{"oversized parent", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.ParentSessionID = strings.Repeat("x", 129)
		}, impersonation.ErrInvalidInput},
		{"unsafe parent", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.ParentSessionID = "ordinary\nparent"
		}, impersonation.ErrInvalidInput},
		{"spaced parent", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.ParentSessionID = "ordinary parent"
		}, impersonation.ErrInvalidInput},
		{"zero parent version", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.ParentSessionVersion = 0
		}, impersonation.ErrInvalidInput},
		{"missing parent expiry", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.ParentExpiresAt = time.Time{}
		}, impersonation.ErrInvalidInput},
		{"missing time", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) { in.At = time.Time{} }, impersonation.ErrInvalidInput},
		{"before approval", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.At = in.Approval.At().Add(-time.Nanosecond)
		}, impersonation.ErrInvalidInput},
		{"at original deadline", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) { in.At = g.ExpiresAt() }, impersonation.ErrExpired},
		{"past original deadline", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.At = g.ExpiresAt().Add(time.Nanosecond)
		}, impersonation.ErrExpired},
		{"parent expires at start", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.ParentExpiresAt = in.At
		}, impersonation.ErrExpired},
		{"parent already expired", func(t *testing.T, g *impersonation.Grant, in *impersonation.ActivationInput) {
			in.ParentExpiresAt = in.At.Add(-time.Nanosecond)
		}, impersonation.ErrExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grant, input := activationFixture(t)
			tc.change(t, &grant, &input)
			got, session, err := impersonation.Activate(grant, input)
			if !errors.Is(err, tc.want) || got.Version() != 0 || session.Bindings().GrantID != "" {
				t.Fatalf("rejected activation returned %v, grant version %d or active metadata", err, got.Version())
			}
		})
	}
}

func TestActivateDoesNotRenewApprovalOrAllowReactivation(t *testing.T) {
	grant, input := activationFixture(t)
	input.At = grant.ExpiresAt().Add(-time.Nanosecond)
	active, session, err := impersonation.Activate(grant, input)
	if err != nil {
		t.Fatal(err)
	}
	if !session.Bindings().ExpiresAt.Equal(input.At.Add(grant.Request().Duration())) {
		t.Fatal("active lifetime was not bounded by approved duration from activation")
	}
	input.ExpectedVersion = 3
	if _, _, err := impersonation.Activate(active, input); !errors.Is(err, impersonation.ErrConflict) {
		t.Fatalf("reactivation error = %v", err)
	}
}

func TestActivateAcceptsDecisionBoundaryAndNativeParentIdentifiers(t *testing.T) {
	for _, parent := range []string{"s", "ordinary-session:actor", strings.Repeat("x", 128), "!~"} {
		t.Run(parent, func(t *testing.T) {
			grant, input := activationFixture(t)
			input.At = input.Approval.At()
			input.ParentSessionID = parent
			_, session, err := impersonation.Activate(grant, input)
			if err != nil {
				t.Fatal(err)
			}
			if !session.Bindings().StartedAt.Equal(input.At) || session.Bindings().ParentSessionID != parent {
				t.Fatal("decision boundary or native parent identifier was changed")
			}
		})
	}
}

func TestActiveSessionImplicitOutputRedactsMetadata(t *testing.T) {
	grant, input := activationFixture(t)
	_, session, err := impersonation.Activate(grant, input)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{fmt.Sprint(session), fmt.Sprintf("%#v", session)} {
		if strings.Contains(output, string(grant.ID())) || strings.Contains(output, input.ParentSessionID) || strings.Contains(output, "sensitive support reason") {
			t.Fatal("implicit output exposed private activation metadata")
		}
	}
	encoded, err := json.Marshal(session)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("active session serialized private metadata")
	}
}
