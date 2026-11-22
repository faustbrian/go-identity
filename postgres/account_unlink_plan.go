package postgres

import (
	"bytes"
	"crypto/sha256"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func accountUnlinkOwnerDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.account-unlink", Version: 1}
}

func accountUnlinkBinding(b identity.CommandBinding) bool {
	return b.OperationID == "identity.account.unlink" && b.SchemaID == "identity-account" && b.SchemaVersion == 1 && b.LinkMode == 0 && b.ActorKind == authorization.SubjectUser && b.RecordID != "" && string(b.ActorID) == string(b.UserID)
}

// This is an additive closed declaration around the historical kernel plan.
// The distinct provider contract prevents link preparation from being treated
// as unlink eligibility, fresh-proof consumption or token cleanup authority.
func encodeAccountUnlinkPlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	if !accountUnlinkBinding(b) || p.CommandCounters == nil || p.Lifecycle == nil || validateOAuthAccountUnlinkAudits(b, p.Audits) != nil {
		return nil, invalidPlan()
	}
	if p.CommandCounters.PolicyVersion == 0 || p.CommandCounters.Fingerprint == ([32]byte{}) {
		return nil, invalidPlan()
	}
	if p.AccountLinkState != nil || p.IdentifierAdmission != nil || p.Delivery != nil || p.CapabilityIssuance != nil {
		return nil, invalidPlan()
	}
	if len(p.Contributors) != 6 || p.Contributors[4] != accountLinkCounterDescriptor() || p.Contributors[5] != accountUnlinkOwnerDescriptor() {
		return nil, invalidPlan()
	}
	if p.Contributors[0] != (ContributorDescriptor{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}) || p.Contributors[1].Owner != "audit/postgres" || p.Contributors[2] != (ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}) || p.Contributors[3] != (ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}) {
		return nil, invalidPlan()
	}
	base := p
	base.Audits = p.Audits[:1]
	base.CommandCounters, base.Contributors = nil, p.Contributors[:4]
	profile := "identity-account-unlink-plan-v1"
	if p.Capability == nil {
		// Original preparation carries the final participant identities, not an
		// invented grant. Its base has only the three domain/effect owners.
		base.Contributors = p.Contributors[:3]
		profile = "identity-account-unlink-preparation-plan-v1"
	}
	wire, err := encodeKernelPlan(b, fp, base)
	if err != nil {
		return nil, err
	}
	d := p.Contributors[5]
	result := cborMap(map[string][]byte{
		"base": cborBytes(wire), "counter": encodeCommandCounterPlan(*p.CommandCounters),
		"profile": cborText(profile), "version": cborUint(1),
		"provider": cborMap(map[string][]byte{"owner": cborText(d.Owner), "contract_id": cborText(d.ContractID), "version": cborUint(uint64(d.Version))}),
	})
	if len(result) > 65536 {
		return nil, invalidPlan()
	}
	return result, nil
}

func decodeAccountUnlinkPlan(b identity.CommandBinding, fp [32]byte, data []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if !accountUnlinkBinding(b) || len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 5)
	r.key("base")
	n, ok := r.head(2)
	// The base is the fixed six/seven-field kernel shape, never a wrapper.
	// This bounds nesting before the historical decoder is entered.
	if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) || r.data[0] != 0xa6 && r.data[0] != 0xa7 {
		return fail()
	}
	base, err := decodeKernelPlan(b, fp, r.data[:int(n)])
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("counter")
	r.expect(5, 2)
	r.key("fingerprint")
	counters := &CommandCounterPlan{}
	r.digest(&counters.Fingerprint)
	r.key("policy_version")
	counters.PolicyVersion = r.number(^uint64(0))
	r.key("profile")
	profile := "identity-account-unlink-plan-v1"
	if base.Capability == nil {
		profile = "identity-account-unlink-preparation-plan-v1"
		base.Contributors = append(base.Contributors, ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1})
	}
	r.consume(cborText(profile))
	r.key("version")
	r.consume(cborUint(1))
	r.key("provider")
	d := readFeaturePlanContributor(&r)
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	base.CommandCounters = counters
	base.Audits = oauthAccountUnlinkAuditPlans(base.Audits[0])
	base.Contributors = append(base.Contributors, accountLinkCounterDescriptor(), d)
	canonical, err := encodeAccountUnlinkPlan(b, fp, base)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	base.Digest = sha256.Sum256(data)
	return base, nil
}

func (c *Coordinator) prepareAccountUnlink(b identity.CommandBinding, command identity.Command, plan CommandPlan) (claimRequest, CommandPlan, *admittedKernelPlan, error) {
	fail := func() (claimRequest, CommandPlan, *admittedKernelPlan, error) {
		return claimRequest{}, CommandPlan{}, nil, invalidPlan()
	}
	spec, _, ok := command.AccountUnlinkCounterCommand()
	if !ok || spec.Binding != b || !accountUnlinkBinding(b) || spec.RevokeProvider || !accountUnlinkProofPlan(spec, plan) {
		return fail()
	}
	q, err := prepareClaim(command, c.keys.retained[c.keys.current])
	if err != nil || !validClaim(q, c.keys) || !bytes.Equal(q.safeFields, cborMap(commandScope(b))) {
		return fail()
	}
	fp := claimFingerprint(c.keys.retained[c.keys.current], q.canonical)
	wire, err := encodeAccountUnlinkPlan(b, fp, plan)
	if err != nil {
		return fail()
	}
	owned, err := decodeAccountUnlinkPlan(b, fp, wire)
	if err != nil {
		return fail()
	}
	admitted, err := c.registry.admitKernelPlan(b, fp, owned)
	if err != nil || admitted.accountUnlink == nil || counterAdmissionParticipant(admitted) == nil {
		return fail()
	}
	owner := admitted.accountUnlink.contributor.(AccountUnlinkContributor)
	if validateCommandCounters(counterAdmissionParticipant(admitted), command, *owned.CommandCounters) != nil || validateAccountUnlink(owner, command, admitted.snapshot()) != nil {
		return fail()
	}
	return q, owned, admitted, nil
}

func accountUnlinkProofPlan(spec identity.AccountUnlinkCommand, plan CommandPlan) bool {
	if plan.Capability == nil || plan.Lifecycle == nil || plan.CommandCounters == nil {
		return false
	}
	proof := spec.Proof.Payload()
	return plan.Capability.CapabilityID == proof.ID && plan.Capability.Purpose == "identity.account.unlink" && plan.Capability.ProofFingerprint == spec.Proof.EnvelopeDigest() && plan.Capability.ExpiresAt.Equal(proof.ExpiresAt) && plan.Capability.MaxUses == proof.MaxUses && plan.Lifecycle.BeforeVersion == spec.Change.ExpectedAccountVersion && plan.Lifecycle.AfterVersion == spec.Change.ExpectedAccountVersion+1
}

func validateAccountUnlink(p AccountUnlinkContributor, command identity.Command, plan CommandPlan) (err error) {
	defer func() {
		if recover() != nil {
			err = invalidPlan()
		}
	}()
	if p.ValidateAccountUnlink(command, plan) != nil {
		return invalidPlan()
	}
	return nil
}
