package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

// This closed two-input envelope distinguishes the original callback state from
// the link grant that can only exist after provider exchange. A nil final grant
// is an explicit preparation declaration, not invented proof or execution
// authority. Installed single-input account-link bytes remain unchanged.
func encodeAccountLinkStatePlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	state := p.AccountLinkState
	if !accountLinkBinding(b) || fp == ([32]byte{}) || state == nil || state.Purpose != "identity.oauth.callback" || state.MaxUses != 1 || state.ReplayKeyVersion == 0 || state.ProofFingerprint == ([32]byte{}) || !postgresExactTime(state.ExpiresAt) || state.ExpiresAt.Nanosecond() != 0 || p.CommandCounters == nil || p.CommandCounters.PolicyVersion == 0 || p.CommandCounters.Fingerprint == ([32]byte{}) || p.Lifecycle == nil || p.IdentifierAdmission != nil || p.Delivery != nil || p.CapabilityIssuance != nil || len(p.Contributors) != 6 || p.Contributors[3] != (ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}) || p.Contributors[4] != accountLinkCounterDescriptor() || p.Contributors[5] != accountLinkOwnerDescriptor() {
		return nil, invalidPlan()
	}
	if p.Contributors[0] != (ContributorDescriptor{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}) || p.Contributors[1].Owner != "audit/postgres" || p.Contributors[2] != (ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}) {
		return nil, invalidPlan()
	}
	if _, err := capability.NewReference(state.CapabilityID, state.Purpose, state.ReplayDigest, state.ExpiresAt); err != nil {
		return nil, invalidPlan()
	}
	if p.Capability != nil && p.Capability.ProofFingerprint == state.ProofFingerprint {
		return nil, invalidPlan()
	}
	base := p
	base.AccountLinkState, base.CommandCounters = nil, nil
	version := uint64(1)
	profile := "identity-account-link-state-plan-v1"
	if len(p.Audits) == 3 {
		if validateOAuthAccountLinkAudits(b, p.Audits) != nil {
			return nil, invalidPlan()
		}
		base.Audits = p.Audits[:1]
		version, profile = 2, "identity-account-link-state-plan-v2"
	}
	count := 3
	if p.Capability != nil {
		count = 4
	}
	base.Contributors = p.Contributors[:count]
	wire, err := encodeKernelPlan(b, fp, base)
	if err != nil {
		return nil, err
	}
	encoded := cborMap(map[string][]byte{
		"base": cborBytes(wire), "state": encodeCapabilityPlan(state),
		"counter": encodeCommandCounterPlan(*p.CommandCounters),
		"profile": cborText(profile), "version": cborUint(version),
		"provider": cborMap(map[string][]byte{"owner": cborText(p.Contributors[5].Owner), "contract_id": cborText(p.Contributors[5].ContractID), "version": cborUint(uint64(p.Contributors[5].Version))}),
	})
	if len(encoded) > 65536 {
		return nil, invalidPlan()
	}
	return encoded, nil
}

func decodeAccountLinkStatePlan(b identity.CommandBinding, fp [32]byte, data []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if !accountLinkBinding(b) || fp == ([32]byte{}) || len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 6)
	r.key("base")
	n, ok := r.head(2)
	// Fixed six/seven-field kernel bases only: wrappers cannot nest or recurse.
	if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) || r.data[0] != 0xa6 && r.data[0] != 0xa7 || !bytes.HasPrefix(r.data[1:], cborText("audits")) {
		return fail()
	}
	base, err := decodeKernelPlan(b, fp, r.data[:int(n)])
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("state")
	r.expect(5, 7)
	state := &CapabilityPlan{}
	r.key("purpose")
	state.Purpose = capability.Purpose(r.string(128))
	r.key("max_uses")
	state.MaxUses = uint32(r.number(math.MaxUint32))
	r.key("expires_at")
	state.ExpiresAt = time.Unix(int64(r.number(253402300799)), 0).UTC()
	r.key("capability_id")
	state.CapabilityID = r.string(256)
	r.key("replay_digest")
	r.digest(&state.ReplayDigest)
	r.key("proof_fingerprint")
	r.digest(&state.ProofFingerprint)
	r.key("replay_key_version")
	state.ReplayKeyVersion = uint32(r.number(math.MaxUint32))
	r.key("counter")
	r.expect(5, 2)
	counters := &CommandCounterPlan{}
	r.key("fingerprint")
	r.digest(&counters.Fingerprint)
	r.key("policy_version")
	counters.PolicyVersion = r.number(math.MaxUint64)
	r.key("profile")
	profile := r.string(64)
	version := uint64(1)
	switch profile {
	case "identity-account-link-state-plan-v1":
	case "identity-account-link-state-plan-v2":
		version = 2
		base.Audits = oauthAccountLinkAuditPlans(base.Audits[0])
	default:
		return fail()
	}
	r.key("version")
	r.consume(cborUint(version))
	r.key("provider")
	provider := readFeaturePlanContributor(&r)
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	if base.Capability == nil {
		base.Contributors = append(base.Contributors, ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1})
	}
	base.AccountLinkState, base.CommandCounters = state, counters
	base.Contributors = append(base.Contributors, accountLinkCounterDescriptor(), provider)
	canonical, err := encodeAccountLinkStatePlan(b, fp, base)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	base.Digest = sha256.Sum256(data)
	return base, nil
}
