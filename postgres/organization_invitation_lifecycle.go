package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	identity "github.com/faustbrian/go-identity"
)

// OrganizationInvitationLifecycleContributor persists invitation acceptance
// and its distinct membership-created event atomically through the existing
// outbox. Neither callback may close/retain Work or perform network IO. The
// secondary event must come from StagedOrganizationInvitationMembership.
type OrganizationInvitationLifecycleContributor interface {
	LifecycleContributor
	PersistOrganizationInvitation(context.Context, Work) error
}

// OrganizationInvitationMembership is the trusted native owner's provisional
// successful membership mutation, never caller authority or a commit receipt.
// BeforeVersion is the actual retained tombstone version (zero only for a new
// member); AfterVersion is its checked successor, not the invitation's version.
type OrganizationInvitationMembership struct {
	OrganizationID              string
	UserID                      identity.UserID
	BeforeVersion, AfterVersion uint64
}

// RecordOrganizationInvitationMembership retains one exact native mutation
// after the owner has successfully written membership in this Work. It verifies
// the frozen original organization/member version and current protected
// consumption invocation; it does not independently inspect owner SQL. Invalid
// or repeated recording poisons Work so an ignored error cannot commit.
func (w Work) RecordOrganizationInvitationMembership(owner OrganizationInvitationConsumptionContributor, mutation OrganizationInvitationMembership) error {
	b, _, _, err := w.FeatureCommandIdentity(owner)
	if err != nil {
		if w.usable() != nil {
			return invalidWork()
		}
		return w.fail(w.state.ctx, invalidWork())
	}
	if _, err := w.OrganizationInvitationConsumption(owner); err != nil {
		return w.fail(w.state.ctx, err)
	}
	if w.state.invitationMembership != nil || w.state.featureApplyCommand == nil || mutation.UserID != b.UserID || !auditSafeID(mutation.OrganizationID) || mutation.BeforeVersion == ^uint64(0) || mutation.AfterVersion != mutation.BeforeVersion+1 {
		return w.fail(w.state.ctx, invalidWork())
	}
	s, ok := w.state.featureApplyCommand.Feature()
	if !ok {
		return w.fail(w.state.ctx, invalidWork())
	}
	matched := 0
	for _, f := range s.Fields {
		switch f.Name {
		case "organization.id":
			if f.Value.Kind != identity.FeatureText || f.Value.Text != mutation.OrganizationID {
				return w.fail(w.state.ctx, invalidWork())
			}
			matched++
		case "organization.member-version":
			if f.Value.Kind != identity.FeatureUint64 || f.Value.Uint64 != mutation.BeforeVersion {
				return w.fail(w.state.ctx, invalidWork())
			}
			matched++
		}
	}
	if matched != 2 {
		return w.fail(w.state.ctx, invalidWork())
	}
	copy := mutation
	w.state.invitationMembership = &copy
	return nil
}

// StagedOrganizationInvitationMembership projects the actual retained member
// mutation only after matching successful primary invitation audit/lifecycle
// staging. Its fixed secondary index1 is part of the closed accept profile;
// primary index0 is reserved for invitation.accepted.v1. Both share command,
// tenant, recipient and primary occurrence time, never invitation versions.
// The safe projection grants no membership and is not an outbox/commit receipt.
func (w Work) StagedOrganizationInvitationMembership() (StagedLifecycle, error) {
	if err := w.usable(); err != nil {
		return StagedLifecycle{}, err
	}
	if w.state.execution == nil || w.state.execution.reservation == nil || !w.state.invitationConsumed || w.state.invitationMembership == nil {
		return StagedLifecycle{}, invalidWork()
	}
	p := w.state.execution.reservation.plan
	if p.feature == nil || p.feature.Operation != organizationInvitationAcceptOperation() || w.state.featureReceipt == nil {
		return StagedLifecycle{}, invalidWork()
	}
	primary, err := w.StagedLifecycle()
	if err != nil || len(primary) != 1 || primary[0].EventIndex != 0 || primary[0].EventType != "invitation.accepted.v1" || primary[0].SubjectType != "invitation" || primary[0].BeforeVersion != 1 || primary[0].AfterVersion != 2 {
		return StagedLifecycle{}, invalidLifecycle()
	}
	b, m := w.state.binding, w.state.invitationMembership
	id := sha256.Sum256(cborMap(map[string][]byte{"profile": cborText("identity-effect-id-v1"), "command_id": cborText(string(b.CommandID)), "class": cborText("lifecycle"), "index": cborUint(1)}))
	return StagedLifecycle{ID: hex.EncodeToString(id[:]), CommandID: b.CommandID, TenantID: b.TenantID, UserID: m.UserID, OperationID: b.OperationID, EventType: "membership.created.v1", EventIndex: 1, SubjectType: "organization", SubjectID: m.OrganizationID, BeforeVersion: m.BeforeVersion, AfterVersion: m.AfterVersion, OccurredAt: primary[0].OccurredAt}, nil
}
