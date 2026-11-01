package postgres

import (
	"bytes"
	"crypto/sha256"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func accountLinkOwnerDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.account-link", Version: 1}
}

func accountLinkCounterDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}
}

func accountLinkBinding(b identity.CommandBinding) bool {
	return b.OperationID == "identity.account.link-token" && b.SchemaID == "identity-account" && b.SchemaVersion == 1 && b.LinkMode == identity.AccountLinkExplicit && b.ActorKind == authorization.SubjectUser && b.RecordID != "" && string(b.ActorID) == string(b.UserID)
}

// This closed envelope extends the existing kernel plan, not its historical
// bytes. A bare kernel declaration cannot omit the counter or provider owner.
func encodeAccountLinkPlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	if !accountLinkBinding(b) || p.CommandCounters == nil || p.CommandCounters.PolicyVersion == 0 || p.CommandCounters.Fingerprint == ([32]byte{}) || p.Capability == nil || p.Lifecycle == nil || p.IdentifierAdmission != nil || p.Delivery != nil || p.CapabilityIssuance != nil || len(p.Contributors) != 6 || p.Contributors[4] != accountLinkCounterDescriptor() || p.Contributors[5] != accountLinkOwnerDescriptor() {
		return nil, invalidPlan()
	}
	if p.Contributors[0] != (ContributorDescriptor{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}) || p.Contributors[1].Owner != "audit/postgres" || p.Contributors[2] != (ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}) || p.Contributors[3] != (ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}) {
		return nil, invalidPlan()
	}
	base := p
	base.CommandCounters, base.Contributors = nil, p.Contributors[:4]
	wire, err := encodeKernelPlan(b, fp, base)
	if err != nil {
		return nil, err
	}
	d := p.Contributors[5]
	result := cborMap(map[string][]byte{
		"base": cborBytes(wire), "counter": encodeCommandCounterPlan(*p.CommandCounters),
		"profile": cborText("identity-account-link-plan-v1"), "version": cborUint(1),
		"provider": cborMap(map[string][]byte{"owner": cborText(d.Owner), "contract_id": cborText(d.ContractID), "version": cborUint(uint64(d.Version))}),
	})
	if len(result) > 65536 {
		return nil, invalidPlan()
	}
	return result, nil
}

func decodeAccountLinkPlan(b identity.CommandBinding, fp [32]byte, data []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if !accountLinkBinding(b) || len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 5)
	r.key("base")
	n, ok := r.head(2)
	// Only the fixed seven-field kernel base is legal. In particular, nested
	// wrappers cannot cause recursion or introduce undeclared participant phases.
	if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) || r.data[0] != 0xa7 {
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
	r.consume(cborText("identity-account-link-plan-v1"))
	r.key("version")
	r.consume(cborUint(1))
	r.key("provider")
	d := readFeaturePlanContributor(&r)
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	base.CommandCounters = counters
	base.Contributors = append(base.Contributors, accountLinkCounterDescriptor(), d)
	canonical, err := encodeAccountLinkPlan(b, fp, base)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	base.Digest = sha256.Sum256(data)
	return base, nil
}

func (c *Coordinator) prepareAccountLink(b identity.CommandBinding, command identity.Command, plan CommandPlan) (claimRequest, CommandPlan, *admittedKernelPlan, error) {
	fail := func() (claimRequest, CommandPlan, *admittedKernelPlan, error) {
		return claimRequest{}, CommandPlan{}, nil, invalidPlan()
	}
	spec, _, ok := command.AccountLinkCounterCommand()
	if !ok || spec.Binding != b || !accountLinkBinding(b) || plan.Capability == nil || plan.Lifecycle == nil || plan.CommandCounters == nil {
		return fail()
	}
	if !accountLinkProofPlan(spec, plan) {
		return fail()
	}
	q, err := prepareClaim(command, c.keys.retained[c.keys.current])
	if err != nil || !validClaim(q, c.keys) || !bytes.Equal(q.safeFields, cborMap(commandScope(b))) {
		return fail()
	}
	fp := claimFingerprint(c.keys.retained[c.keys.current], q.canonical)
	wire, err := encodeAccountLinkPlan(b, fp, plan)
	if err != nil {
		return fail()
	}
	owned, err := decodeAccountLinkPlan(b, fp, wire)
	if err != nil {
		return fail()
	}
	admitted, err := c.registry.admitKernelPlan(b, fp, owned)
	if err != nil || admitted.accountLink == nil || counterAdmissionParticipant(admitted) == nil {
		return fail()
	}
	if validateCommandCounters(counterAdmissionParticipant(admitted), command, *owned.CommandCounters) != nil || validateAccountLink(admitted.accountLink.contributor.(AccountLinkContributor), command, admitted.snapshot()) != nil {
		return fail()
	}
	return q, owned, admitted, nil
}

func accountLinkProofPlan(spec identity.AccountLinkCommand, plan CommandPlan) bool {
	if plan.Capability == nil || plan.Lifecycle == nil {
		return false
	}
	proof := spec.Proof.Payload()
	return plan.Capability.CapabilityID == proof.ID && plan.Capability.Purpose == "identity.account.link-token" && plan.Capability.ProofFingerprint == spec.Proof.EnvelopeDigest() && plan.Capability.ExpiresAt.Equal(proof.ExpiresAt) && plan.Capability.MaxUses == proof.MaxUses && plan.Lifecycle.BeforeVersion == spec.Change.ExpectedAccountVersion && plan.Lifecycle.AfterVersion == spec.Change.Account.Version
}

func validateAccountLink(p AccountLinkContributor, command identity.Command, plan CommandPlan) (err error) {
	defer func() {
		if recover() != nil {
			err = invalidPlan()
		}
	}()
	if p.ValidateAccountLink(command, plan) != nil {
		return invalidPlan()
	}
	return nil
}
