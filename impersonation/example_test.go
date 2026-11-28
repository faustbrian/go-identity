package impersonation_test

import (
	"fmt"
	"time"

	"github.com/faustbrian/go-identity/impersonation"
)

func ExampleApprove() {
	// The durable adapter separately authenticates and authorizes both ordinary
	// administrators against current target/scoped policy before applying this
	// deterministic transition. These values establish no authority themselves.
	actor, _ := impersonation.NewActor("tenant", "requester")
	target, _ := impersonation.NewTarget("tenant", "customer", 7)
	scope, _ := impersonation.NewScope([]string{"profile:read"})
	reason, _ := impersonation.NewReason("Customer-authorized support")
	policy, _ := impersonation.NewPolicy("support-read", 3)
	request, _ := impersonation.NewRequest(impersonation.RequestInput{
		Tenant: "tenant", Actor: actor, Target: target, Scope: scope,
		Reason: reason, Duration: 5 * time.Minute, Policy: policy,
	})
	at := time.Date(2026, 11, 28, 9, 0, 0, 0, time.UTC)
	// The adapter generates a unique random grant ID; this is an example ID.
	pending, _ := impersonation.NewPendingGrant("AQEBAQEBAQEBAQEBAQEBAQ", request, at)
	approver, _ := impersonation.NewActor("tenant", "reviewer")
	approvalReason, _ := impersonation.NewReason("Verified support scope")
	approved, approval, err := impersonation.Approve(pending, impersonation.ApprovalInput{
		GrantID: pending.ID(), ExpectedVersion: pending.Version(), Request: request,
		Approver: approver, Reason: approvalReason, At: at.Add(time.Minute),
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(pending.Status(), approved.Status(), approved.Version())
	fmt.Println(approval.Approver().User(), approval.RequestVersion())
	// Output:
	// pending_approval approved 2
	// reviewer 1
}
