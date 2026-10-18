package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// OrganizationInvitationOriginPlan preserves the original invitation-send
// organization in the existing frozen command declaration. It is historical
// correlation, never current membership, permission or an execution lease.
// Native owners must supply the same values as the immutable original command's
// organization.id and organization.version fields before preparation starts.
type OrganizationInvitationOriginPlan struct {
	OrganizationID      string
	OrganizationVersion uint64
}

func cloneOrganizationInvitationOrigin(p *OrganizationInvitationOriginPlan) *OrganizationInvitationOriginPlan {
	if p == nil {
		return nil
	}
	x := *p
	x.OrganizationID = strings.Clone(x.OrganizationID)
	return &x
}

func validOrganizationInvitationOrigin(p CommandPlan) bool {
	o := p.OrganizationInvitationOrigin
	return o != nil && queryScopeText(o.OrganizationID) && o.OrganizationVersion > 0 &&
		p.Feature != nil && p.Feature.Operation == organizationInvitationSendOperation() &&
		p.Feature.Contributor == organizationInvitationDescriptor() && p.SubjectType == "invitation" &&
		p.MFACompletion == nil && p.MFAContinuation == nil && p.MagicLinkRegistration == nil &&
		!p.SignupAcceptance && !p.MagicLinkRequestAcceptance && p.Capability == nil &&
		p.IdentifierAdmission == nil && p.OTP == nil && p.RiskEvidence == nil &&
		p.CaptchaEvidence == nil && !p.CaptchaReplayReservation
}

func validateOrganizationInvitationOriginCommand(command identity.Command, p CommandPlan) error {
	if p.OrganizationInvitationOrigin == nil {
		return nil
	}
	s, ok := commandFeature(command)
	if !ok || !validOrganizationInvitationOrigin(p) || s.Operation != p.Feature.Operation {
		return invalidPlan()
	}
	matched := 0
	for _, f := range s.Fields {
		switch f.Name {
		case "organization.id":
			if f.Value.Kind != identity.FeatureText || f.Value.Text != p.OrganizationInvitationOrigin.OrganizationID {
				return invalidPlan()
			}
			matched++
		case "organization.version":
			if f.Value.Kind != identity.FeatureUint64 || f.Value.Uint64 != p.OrganizationInvitationOrigin.OrganizationVersion {
				return invalidPlan()
			}
			matched++
		}
	}
	if matched != 2 {
		return invalidPlan()
	}
	return nil
}

// This fixed-depth envelope is inside optional issuance/delivery wrappers.
// Its ordinary base cannot itself be an envelope, bounding hostile recursion.
// Nil origin retains all previously shipped plan encodings unchanged.
func encodeOrganizationInvitationOrigin(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	if !validOrganizationInvitationOrigin(p) || p.Delivery != nil || p.CapabilityIssuance != nil {
		return nil, invalidPlan()
	}
	base := p
	base.OrganizationInvitationOrigin = nil
	wire, err := encodeFeaturePlan(b, fp, base)
	if err != nil || len(wire) == 0 || wire[0] < 0xa7 || wire[0] > 0xab {
		return nil, invalidPlan()
	}
	o := p.OrganizationInvitationOrigin
	result := cborMap(map[string][]byte{"base": cborBytes(wire), "profile": cborText("organization-invitation-origin-v1"), "version": cborUint(1), "organization_id": cborText(o.OrganizationID), "organization_version": cborUint(o.OrganizationVersion)})
	if len(result) > 65536 {
		return nil, invalidPlan()
	}
	return result, nil
}

func decodeOrganizationInvitationOrigin(b identity.CommandBinding, fp [32]byte, data []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 5)
	r.key("base")
	n, ok := r.head(2)
	if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) || r.data[0] < 0xa7 || r.data[0] > 0xab {
		return fail()
	}
	p, err := decodeFeaturePlan(b, fp, r.data[:int(n)])
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("profile")
	r.consume(cborText("organization-invitation-origin-v1"))
	r.key("version")
	r.consume(cborUint(1))
	o := &OrganizationInvitationOriginPlan{}
	r.key("organization_id")
	o.OrganizationID = r.string(128)
	r.key("organization_version")
	o.OrganizationVersion = r.number(math.MaxUint64)
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	p.OrganizationInvitationOrigin = o
	canonical, err := encodeFeaturePlan(b, fp, p)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	p.Digest = sha256.Sum256(data)
	return p, nil
}

// QueryOrganizationInvitationOrigin reads original safe organization correlation
// from the sole command journal, including preparation-start history without a
// domain row or generated output. The current query policy and exact registered
// native invitation-send owner are required. Callers must authenticate a current
// session and separately authorize access to the returned organization before
// calling RecoverFeatureCommand; this read grants no recovery/execution authority.
//
// Returns immutable scalar copies and historical outcome, never bearer, output,
// current permissions or a renewed deadline. Legacy, incomplete and corrupt
// origin declarations fail closed; absence never proves noncommit. A classified
// terminal failure may accompany valid metadata, matching QueryCommand. Policy
// runs outside SQL locks. The existing maximum/earlier caller deadline bounds
// this uncached read; concurrent calls borrow the coordinator's immutable config.
func (c *Coordinator) QueryOrganizationInvitationOrigin(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext, owner OrganizationInvitationIssuanceContributor) (OrganizationInvitationOriginPlan, CommandRecord, error) {
	if c == nil || c.registry == nil || q.OperationID != organizationInvitationSendOperation().OperationID {
		return OrganizationInvitationOriginPlan{}, CommandRecord{}, invalidPreparation()
	}
	feature := FeatureRegistration{Contributor: organizationInvitationDescriptor(), Operation: organizationInvitationSendOperation()}
	entry, err := c.registry.selectFeatureOperation(feature)
	if err != nil || !sameParticipant(entry.contributor, owner) {
		return OrganizationInvitationOriginPlan{}, CommandRecord{}, invalidPreparation()
	}
	var origin OrganizationInvitationOriginPlan
	receipt, err := c.queryCommandReceiptChecked(ctx, q, caller, func(observed commandObservation) error {
		binding, operation, e := commandObservationScope(q, observed, nil)
		if e != nil || operation == nil || *operation != feature.Operation || observed.fingerprintKeyVersion < 1 || observed.fingerprintKeyVersion > math.MaxUint32 || c.keys.retained[uint32(observed.fingerprintKeyVersion)] == ([32]byte{}) {
			return identity.UnavailableError{}
		}
		p, _, e := observedCommandPlan(binding, operation, observed)
		if e != nil || !validOrganizationInvitationOrigin(p) || *p.Feature != feature {
			return identity.UnavailableError{}
		}
		origin = *p.OrganizationInvitationOrigin
		return nil
	})
	if receipt.Outcome == identity.CommitOutcomeInvalid {
		return OrganizationInvitationOriginPlan{}, CommandRecord{}, err
	}
	return origin, commandRecord(receipt), err
}
