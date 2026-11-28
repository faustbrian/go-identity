package impersonation_test

import (
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/impersonation"
)

func TestQuorumActivationPreservesCompleteApprovedLineage(t *testing.T) {
	for _, required := range []int{1, 2, 3, 32} {
		for _, parentLifetime := range []time.Duration{5 * time.Minute, time.Hour} {
			t.Run(strconv.Itoa(required)+"/"+parentLifetime.String(), func(t *testing.T) {
				grant, input := quorumActivationFixture(t, required)
				input.ParentExpiresAt = input.At.Add(parentLifetime)
				evidence := grant.Approvals()
				before := slices.Clone(evidence)
				active, session, err := impersonation.ActivateWithQuorum(grant, input, evidence)
				if err != nil {
					t.Fatal(err)
				}
				if active.Status() != impersonation.StatusActive || active.Version() != grant.Version()+1 || !active.ExpiresAt().Equal(grant.ExpiresAt()) || !slices.Equal(active.Approvals(), before) {
					t.Fatal("activation lost exact version, approvals or original deadline")
				}
				binding := session.Bindings()
				if binding.GrantID != grant.ID() || binding.GrantVersion != active.Version() || binding.TenantID != grant.Request().Tenant() || binding.ActorID != grant.Request().Actor().User() || binding.TargetID != grant.Request().Target().User() || binding.TargetVersion != grant.Request().Target().Version() || binding.Policy != grant.Request().Policy() {
					t.Fatal("activation changed approved identities, target version or policy")
				}
				wantExpiry := input.At.Add(grant.Request().Duration())
				if input.ParentExpiresAt.Before(wantExpiry) {
					wantExpiry = input.ParentExpiresAt
				}
				if binding.ParentSessionID != input.ParentSessionID || binding.ParentSessionVersion != input.ParentSessionVersion || !binding.StartedAt.Equal(input.At) || !binding.ExpiresAt.Equal(wantExpiry) || !slices.Equal(binding.Scope.Permissions(), grant.Request().Scope().Permissions()) {
					t.Fatal("activation lost parent binding, scope or earliest session expiry")
				}
				if grant.Status() != impersonation.StatusApproved || grant.Version() != uint64(required+1) || !slices.Equal(grant.Approvals(), before) || !slices.Equal(evidence, before) {
					t.Fatal("activation mutated original grant or supplied evidence")
				}
				evidence[0] = impersonation.Approval{}
				permissions := binding.Scope.Permissions()
				permissions[0] = "admin:*"
				if !slices.Equal(active.Approvals(), before) || !slices.Equal(session.Bindings().Scope.Permissions(), grant.Request().Scope().Permissions()) {
					t.Fatal("active metadata aliases caller evidence or scope")
				}
				input.ExpectedVersion = active.Version()
				result, repeated, err := impersonation.ActivateWithQuorum(active, input, active.Approvals())
				assertQuorumActivationRejected(t, result, repeated, err, impersonation.ErrConflict)
			})
		}
	}
}

func TestQuorumActivationOnePreservesLegacyEntryPoint(t *testing.T) {
	grant, input := quorumActivationFixture(t, 1)
	active, session, err := impersonation.ActivateWithQuorum(grant, input, grant.Approvals())
	if err != nil {
		t.Fatal(err)
	}
	input.Approval = grant.Approvals()[0]
	legacy, legacySession, err := impersonation.Activate(grant, input)
	if err != nil || !reflect.DeepEqual(active, legacy) || !reflect.DeepEqual(session, legacySession) {
		t.Fatalf("one-approval entry points diverged: %v", err)
	}
	grant, input = quorumActivationFixture(t, 2)
	input.Approval = grant.Approvals()[1]
	result, rejected, err := impersonation.Activate(grant, input)
	assertQuorumActivationRejected(t, result, rejected, err, impersonation.ErrConflict)
	input.Actor = impersonation.Actor{}
	result, rejected, err = impersonation.Activate(grant, input)
	assertQuorumActivationRejected(t, result, rejected, err, impersonation.ErrInvalidInput)
}

func TestQuorumActivationRejectsIncompleteOrMismatchedEvidence(t *testing.T) {
	tests := []struct {
		name   string
		change func(*testing.T, *impersonation.Grant, *impersonation.ActivationInput, *[]impersonation.Approval)
		want   error
	}{
		{"zero grant", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			*grant = impersonation.Grant{}
		}, impersonation.ErrConflict},
		{"pending", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			pending := quorumPendingGrant(t, 2)
			var err error
			*grant, _, err = impersonation.Approve(pending, quorumApprovalInput(t, pending, "approver-0"))
			if err != nil {
				t.Fatal(err)
			}
			input.ExpectedVersion = grant.Version()
			*evidence = grant.Approvals()
		}, impersonation.ErrConflict},
		{"missing", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			*evidence = nil
		}, impersonation.ErrConflict},
		{"too few", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			*evidence = (*evidence)[:1]
		}, impersonation.ErrConflict},
		{"too many", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			*evidence = append(*evidence, (*evidence)[0])
		}, impersonation.ErrConflict},
		{"duplicate", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			(*evidence)[1] = (*evidence)[0]
		}, impersonation.ErrConflict},
		{"reordered", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			(*evidence)[0], (*evidence)[1] = (*evidence)[1], (*evidence)[0]
		}, impersonation.ErrConflict},
		{"zero decision", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			(*evidence)[0] = impersonation.Approval{}
		}, impersonation.ErrConflict},
		{"substituted decision", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			pending := quorumPendingGrant(t, 2)
			_, replacement, err := impersonation.Approve(pending, quorumApprovalInput(t, pending, "substituted-approver"))
			if err != nil {
				t.Fatal(err)
			}
			(*evidence)[0] = replacement
		}, impersonation.ErrConflict},
		{"foreign grant decision", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			pending, err := impersonation.NewPendingGrant("AgICAgICAgICAgICAgICAg", grant.Request(), grant.RequestedAt())
			if err != nil {
				t.Fatal(err)
			}
			_, replacement, err := impersonation.Approve(pending, quorumApprovalInput(t, pending, "approver-0"))
			if err != nil {
				t.Fatal(err)
			}
			(*evidence)[0] = replacement
		}, impersonation.ErrConflict},
		{"two approval authorities", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.Approval = (*evidence)[1]
		}, impersonation.ErrConflict},
		{"wrong grant id", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.GrantID = "AgICAgICAgICAgICAgICAg"
		}, impersonation.ErrConflict},
		{"stale version", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.ExpectedVersion--
		}, impersonation.ErrConflict},
		{"future version", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.ExpectedVersion++
		}, impersonation.ErrConflict},
		{"wrong actor", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.Actor = (*evidence)[0].Approver()
		}, impersonation.ErrConflict},
		{"wrong target", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.CurrentTarget, _ = impersonation.NewTarget("tenant", "target", 8)
		}, impersonation.ErrConflict},
		{"changed quorum", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.CurrentPolicy, _ = impersonation.NewPolicyWithQuorum("support", 3, 1)
		}, impersonation.ErrConflict},
		{"changed policy revision", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.CurrentPolicy, _ = impersonation.NewPolicyWithQuorum("support", 4, 2)
		}, impersonation.ErrConflict},
		{"zero actor", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.Actor = impersonation.Actor{}
		}, impersonation.ErrInvalidInput},
		{"missing parent", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.ParentSessionID = ""
		}, impersonation.ErrInvalidInput},
		{"oversized parent", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.ParentSessionID = strings.Repeat("x", 129)
		}, impersonation.ErrInvalidInput},
		{"invalid parent", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.ParentSessionID = "ordinary parent"
		}, impersonation.ErrInvalidInput},
		{"zero parent version", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.ParentSessionVersion = 0
		}, impersonation.ErrInvalidInput},
		{"zero parent expiry", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.ParentExpiresAt = time.Time{}
		}, impersonation.ErrInvalidInput},
		{"zero time", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.At = time.Time{}
		}, impersonation.ErrInvalidInput},
		{"before decision", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.At = (*evidence)[0].At().Add(-time.Nanosecond)
		}, impersonation.ErrInvalidInput},
		{"at approval deadline", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.At = grant.ExpiresAt()
		}, impersonation.ErrExpired},
		{"parent expires at activation", func(t *testing.T, grant *impersonation.Grant, input *impersonation.ActivationInput, evidence *[]impersonation.Approval) {
			input.ParentExpiresAt = input.At
		}, impersonation.ErrExpired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			grant, input := quorumActivationFixture(t, 2)
			evidence := grant.Approvals()
			test.change(t, &grant, &input, &evidence)
			before := grant.Approvals()
			status, version := grant.Status(), grant.Version()
			result, session, err := impersonation.ActivateWithQuorum(grant, input, evidence)
			assertQuorumActivationRejected(t, result, session, err, test.want)
			if grant.Status() != status || grant.Version() != version || !slices.Equal(grant.Approvals(), before) {
				t.Fatal("rejected activation mutated original grant")
			}
		})
	}
}

func TestQuorumActivationChecksEveryDecisionTime(t *testing.T) {
	grant := quorumPendingGrant(t, 3)
	for index, offset := range []time.Duration{3 * time.Minute, time.Minute, 2 * time.Minute} {
		input := quorumApprovalInput(t, grant, "approver-"+strconv.Itoa(index))
		input.At = grant.RequestedAt().Add(offset)
		next, _, err := impersonation.Approve(grant, input)
		if err != nil {
			t.Fatal(err)
		}
		grant = next
	}
	input := quorumActivationInput(grant)
	input.At = grant.RequestedAt().Add(2*time.Minute + time.Second)
	result, session, err := impersonation.ActivateWithQuorum(grant, input, grant.Approvals())
	assertQuorumActivationRejected(t, result, session, err, impersonation.ErrInvalidInput)
	input.At = grant.RequestedAt().Add(3 * time.Minute)
	if _, _, err := impersonation.ActivateWithQuorum(grant, input, grant.Approvals()); err != nil {
		t.Fatalf("activation at latest retained decision time rejected: %v", err)
	}
}

func quorumActivationFixture(t *testing.T, required int) (impersonation.Grant, impersonation.ActivationInput) {
	t.Helper()
	grant := quorumPendingGrant(t, required)
	for index := range required {
		next, _, err := impersonation.Approve(grant, quorumApprovalInput(t, grant, "approver-"+strconv.Itoa(index)))
		if err != nil {
			t.Fatal(err)
		}
		grant = next
	}
	return grant, quorumActivationInput(grant)
}

func quorumActivationInput(grant impersonation.Grant) impersonation.ActivationInput {
	at := grant.RequestedAt().Add(4 * time.Minute)
	return impersonation.ActivationInput{GrantID: grant.ID(), ExpectedVersion: grant.Version(), Actor: grant.Request().Actor(), CurrentTarget: grant.Request().Target(), CurrentPolicy: grant.Request().Policy(), ParentSessionID: "ordinary-session:actor", ParentSessionVersion: 9, ParentExpiresAt: at.Add(time.Hour), At: at}
}

func assertQuorumActivationRejected(t *testing.T, grant impersonation.Grant, session impersonation.ActiveSession, err, want error) {
	t.Helper()
	if !errors.Is(err, want) || !reflect.DeepEqual(grant, impersonation.Grant{}) || !reflect.DeepEqual(session, impersonation.ActiveSession{}) {
		t.Fatalf("activation returned nonzero outputs or wrong error: %v; want %v", err, want)
	}
}
