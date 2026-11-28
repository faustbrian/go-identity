package impersonationpostgres

import (
	"bytes"
	"testing"

	"github.com/faustbrian/go-identity/impersonation"
)

func TestActivationApprovalRequiresExactOriginalAuthorityEvidence(t *testing.T) {
	ctx := t.Context()
	envelopes, _ := newCustodyTestService(t)
	original := custodyTestOriginal(t).request
	grant := grantRecord{tenant: original.Tenant(), id: "AQEBAQEBAQEBAQEBAQEBAQ",
		requester: original.Actor().User(), target: original.Target().User(), digest: original.Digest()}
	decision := approvalRecord{commandID: "AgICAgICAgICAgICAgICAg", approver: "review-admin"}
	reason, err := impersonation.NewReason("private activation decision")
	if err != nil {
		t.Fatal(err)
	}
	epoch := approvalEpoch{userVersion: 5, authorizationVersion: 8, namespace: "admin-policy"}
	decision.payload, err = sealActivationApproval(ctx, envelopes, "custody-v1", grant, decision, reason, epoch)
	if err != nil || bytes.Contains(decision.payload, []byte(reason.StorageText())) {
		t.Fatal("activation evidence did not seal the original authority without plaintext", err)
	}
	gotReason, gotEpoch, err := openActivationApproval(ctx, envelopes, grant, decision)
	if err != nil || gotReason != reason || gotEpoch != epoch {
		t.Fatal("original approval authority did not round trip", err)
	}
	for _, variant := range []struct {
		name  string
		alter func(*grantRecord, *approvalRecord)
	}{
		{"another decision", func(_ *grantRecord, a *approvalRecord) { a.commandID = "AwMDAwMDAwMDAwMDAwMDAw" }},
		{"another tenant", func(g *grantRecord, _ *approvalRecord) { g.tenant = "other-tenant" }},
		{"another approver", func(_ *grantRecord, a *approvalRecord) { a.approver = "other-admin" }},
		{"another intent", func(g *grantRecord, _ *approvalRecord) { g.digest[0] ^= 1 }},
		{"another target", func(g *grantRecord, _ *approvalRecord) { g.target = "other-target" }},
	} {
		t.Run(variant.name, func(t *testing.T) {
			foreign, changed := grant, decision
			variant.alter(&foreign, &changed)
			if reason, epoch, err := openActivationApproval(ctx, envelopes, foreign, changed); err == nil || reason != (impersonation.Reason{}) || epoch != (approvalEpoch{}) {
				t.Fatal("substituted custody yielded approval authority")
			}
		})
	}
	legacy, err := sealApprovalReason(ctx, envelopes, "custody-v1", grant.tenant, grant.id, grant.requester, grant.target, decision.approver, grant.digest, reason)
	if err != nil {
		t.Fatal(err)
	}
	decision.payload = legacy
	if reason, epoch, err := openActivationApproval(ctx, envelopes, grant, decision); err == nil || reason != (impersonation.Reason{}) || epoch != (approvalEpoch{}) {
		t.Fatal("legacy approval gained invented activation authority")
	}
	if _, err := sealActivationApproval(ctx, envelopes, "custody-v1", grant, decision, reason, approvalEpoch{userVersion: 1, namespace: "admin-policy"}); err == nil {
		t.Fatal("an absent authorization epoch was accepted")
	}
}
