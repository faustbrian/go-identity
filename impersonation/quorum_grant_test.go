package impersonation_test

import (
	"errors"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
)

func TestQuorumApprovalSequencePreservesExactIntentAndDeadline(t *testing.T) {
	for _, required := range []int{1, 2, 3, 32} {
		t.Run(strconv.Itoa(required), func(t *testing.T) {
			grant := quorumPendingGrant(t, required)
			original := grant
			var decisions []impersonation.Approval
			for count := 1; count <= required; count++ {
				before := grant
				beforeApprovals := before.Approvals()
				input := quorumApprovalInput(t, grant, "approver-"+strconv.Itoa(count))
				next, approval, err := impersonation.Approve(grant, input)
				if err != nil {
					t.Fatalf("approval %d of %d: %v", count, required, err)
				}
				wantStatus := impersonation.StatusPendingApproval
				if count == required {
					wantStatus = impersonation.StatusApproved
				}
				if next.Status() != wantStatus || next.Version() != uint64(count+1) {
					t.Fatalf("approval %d: status=%s version=%d", count, next.Status(), next.Version())
				}
				if approval.GrantID() != original.ID() || approval.RequestVersion() != before.Version() || approval.RequestDigest() != original.Request().Digest() || approval.Approver() != input.Approver || approval.Reason() != input.Reason || !approval.At().Equal(input.At) {
					t.Fatalf("approval %d lost exact prior-version decision binding", count)
				}
				decisions = append(decisions, approval)
				if !slices.Equal(next.Approvals(), decisions) {
					t.Fatalf("approval %d lost ordered decisions", count)
				}
				if !next.RequestedAt().Equal(original.RequestedAt()) || !next.ExpiresAt().Equal(original.ExpiresAt()) || next.Request().Digest() != original.Request().Digest() {
					t.Fatalf("approval %d changed original intent or deadline", count)
				}
				if before.Status() != impersonation.StatusPendingApproval || before.Version() != uint64(count) || !slices.Equal(before.Approvals(), beforeApprovals) {
					t.Fatalf("approval %d mutated its prior grant", count)
				}
				grant = next
			}
			if original.Version() != 1 || original.Status() != impersonation.StatusPendingApproval || len(original.Approvals()) != 0 {
				t.Fatal("approvals mutated the original pending snapshot")
			}
			afterQuorum := quorumApprovalInput(t, grant, "extra-approver")
			result, decision, err := impersonation.Approve(grant, afterQuorum)
			if !errors.Is(err, impersonation.ErrConflict) || !reflect.DeepEqual(result, impersonation.Grant{}) || decision != (impersonation.Approval{}) {
				t.Fatal("approved grant accepted another decision or returned nonzero results")
			}
		})
	}
}

func TestQuorumApprovalRejectsInvalidPendingDecisionWithoutMutation(t *testing.T) {
	grant := quorumPendingGrant(t, 4)
	for _, user := range []string{"first-approver", "second-approver"} {
		next, _, err := impersonation.Approve(grant, quorumApprovalInput(t, grant, user))
		if err != nil {
			t.Fatal(err)
		}
		grant = next
	}
	before := grant.Approvals()
	tests := []struct {
		name   string
		change func(*impersonation.ApprovalInput)
		want   error
	}{
		{"first duplicate", func(input *impersonation.ApprovalInput) { input.Approver = before[0].Approver() }, impersonation.ErrConflict},
		{"latest duplicate", func(input *impersonation.ApprovalInput) { input.Approver = before[1].Approver() }, impersonation.ErrConflict},
		{"requester", func(input *impersonation.ApprovalInput) { input.Approver = grant.Request().Actor() }, impersonation.ErrConflict},
		{"target", func(input *impersonation.ApprovalInput) {
			input.Approver, _ = impersonation.NewActor("tenant", "target")
		}, impersonation.ErrConflict},
		{"foreign tenant", func(input *impersonation.ApprovalInput) {
			input.Approver, _ = impersonation.NewActor("other-tenant", "third-approver")
		}, impersonation.ErrConflict},
		{"stale initial version", func(input *impersonation.ApprovalInput) { input.ExpectedVersion = 1 }, impersonation.ErrConflict},
		{"stale previous version", func(input *impersonation.ApprovalInput) { input.ExpectedVersion-- }, impersonation.ErrConflict},
		{"future version", func(input *impersonation.ApprovalInput) { input.ExpectedVersion++ }, impersonation.ErrConflict},
		{"wrong grant", func(input *impersonation.ApprovalInput) { input.GrantID = "BBBBBBBBBBBBBBBBBBBBBQ" }, impersonation.ErrConflict},
		{"changed quorum", func(input *impersonation.ApprovalInput) {
			changed := grant.Request().Input()
			changed.Policy, _ = impersonation.NewPolicyWithQuorum("support", 3, 3)
			input.Request, _ = impersonation.NewRequest(changed)
		}, impersonation.ErrConflict},
		{"expired deadline", func(input *impersonation.ApprovalInput) { input.At = grant.ExpiresAt() }, impersonation.ErrExpired},
		{"past deadline", func(input *impersonation.ApprovalInput) { input.At = grant.ExpiresAt().Add(time.Nanosecond) }, impersonation.ErrExpired},
		{"before request", func(input *impersonation.ApprovalInput) { input.At = grant.RequestedAt().Add(-time.Nanosecond) }, impersonation.ErrInvalidInput},
		{"zero actor", func(input *impersonation.ApprovalInput) { input.Approver = impersonation.Actor{} }, impersonation.ErrInvalidInput},
		{"zero reason", func(input *impersonation.ApprovalInput) { input.Reason = impersonation.Reason{} }, impersonation.ErrInvalidInput},
		{"zero time", func(input *impersonation.ApprovalInput) { input.At = time.Time{} }, impersonation.ErrInvalidInput},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := quorumApprovalInput(t, grant, "third-approver")
			test.change(&input)
			result, approval, err := impersonation.Approve(grant, input)
			if !errors.Is(err, test.want) || !reflect.DeepEqual(result, impersonation.Grant{}) || approval != (impersonation.Approval{}) {
				t.Fatalf("invalid pending decision returned nonzero result or wrong error: %v", err)
			}
			if grant.Status() != impersonation.StatusPendingApproval || grant.Version() != 3 || !slices.Equal(grant.Approvals(), before) {
				t.Fatal("rejected decision mutated pending grant")
			}
		})
	}
}

func TestQuorumApprovalSnapshotsOwnTheirDecisionStorage(t *testing.T) {
	grant := quorumPendingGrant(t, 4)
	for _, user := range []string{"first-approver", "second-approver", "third-approver"} {
		next, _, err := impersonation.Approve(grant, quorumApprovalInput(t, grant, user))
		if err != nil {
			t.Fatal(err)
		}
		grant = next
	}
	retained := slices.Clone(grant.Approvals())
	callerCopy := grant.Approvals()
	callerCopy[0] = impersonation.Approval{}
	callerCopy = append(callerCopy, impersonation.Approval{})
	if !slices.Equal(grant.Approvals(), retained) {
		t.Fatal("caller-owned projection mutated retained decisions")
	}
	first, firstApproval, err := impersonation.Approve(grant, quorumApprovalInput(t, grant, "fourth-approver"))
	if err != nil {
		t.Fatal(err)
	}
	second, secondApproval, err := impersonation.Approve(grant, quorumApprovalInput(t, grant, "alternative-fourth"))
	if err != nil {
		t.Fatal(err)
	}
	if got := first.Approvals(); len(got) != 4 || got[3] != firstApproval {
		t.Fatal("sibling transition overwrote first result")
	}
	if got := second.Approvals(); len(got) != 4 || got[3] != secondApproval {
		t.Fatal("second result lost its own decision")
	}
	if !slices.Equal(grant.Approvals(), retained) || grant.Status() != impersonation.StatusPendingApproval || grant.Version() != 4 {
		t.Fatal("sibling transitions mutated their common pending snapshot")
	}
}

func quorumPendingGrant(t *testing.T, required int) impersonation.Grant {
	t.Helper()
	input := requestInput(t)
	policy, err := impersonation.NewPolicyWithQuorum("support", 3, required)
	if err != nil {
		t.Fatal(err)
	}
	input.Policy = policy
	request, err := impersonation.NewRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := impersonation.NewPendingGrant("AQEBAQEBAQEBAQEBAQEBAQ", request, time.Date(2026, 11, 28, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func quorumApprovalInput(t *testing.T, grant impersonation.Grant, user string) impersonation.ApprovalInput {
	t.Helper()
	actor, err := impersonation.NewActor("tenant", identity.UserID(user))
	if err != nil {
		t.Fatal(err)
	}
	reason, err := impersonation.NewReason("independent decision by " + user)
	if err != nil {
		t.Fatal(err)
	}
	return impersonation.ApprovalInput{GrantID: grant.ID(), ExpectedVersion: grant.Version(), Request: grant.Request(), Approver: actor, Reason: reason, At: grant.RequestedAt().Add(time.Duration(grant.Version()) * time.Second)}
}
