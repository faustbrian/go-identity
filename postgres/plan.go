package postgres

import (
	"crypto/sha256"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// CommandPlan is the complete declaration supplied by a PostgreSQL composition
// adapter before reservation. Contributors are ordered exact registry entries;
// Audits declare mandatory event slots, and Digest binds this declaration to
// the exact command and its authoritative retained-key fingerprint. Callers
// must not mutate its slices during admission. Admission owns copies, so later
// changes do not affect execution. Zero is invalid. This value conveys no
// transaction authority. Typed one-time/feature inputs and public Coordinator
// admission remain under development; the current kernel-only profile cannot
// admit those contributors by name alone.
type CommandPlan struct {
	Contributors []ContributorDescriptor
	Audits       []AuditPlan
	Digest       [32]byte
}

// KernelPlanDigest returns a domain-separated SHA-256 digest of the current
// kernel-only plan, command binding and nonzero authoritative fingerprint.
// It uses deterministic CBOR and preserves contributor order and every audit
// field. Digest itself is excluded. This is binding, not authentication or
// proof that the fingerprint is authoritative: the sole coordinator must
// resolve retained fingerprint keys and compute it from the typed command.
// Exactly one identity/postgres and one audit/postgres contributor are required;
// feature/one-time contributors without typed inputs are rejected, not silently
// omitted. Invalid inputs return redacted identity.InvalidInputError. It does
// no I/O or callbacks. Concurrent calls require immutable caller-owned inputs.
func KernelPlanDigest(binding identity.CommandBinding, fingerprint [32]byte, plan CommandPlan) ([32]byte, error) {
	probe := identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeInProgress, RetryAfter: time.Microsecond}
	if probe.Validate() != nil || fingerprint == ([32]byte{}) || len(plan.Contributors) != 2 || validateKernelAuditPlans(binding, plan.Audits) != nil {
		return [32]byte{}, invalidPlan()
	}
	domains, audits := 0, 0
	contributors := make([][]byte, len(plan.Contributors))
	seen := make(map[string]bool, len(plan.Contributors))
	for i, d := range plan.Contributors {
		if !validContributorDescriptor(d) || seen[d.ContractID] {
			return [32]byte{}, invalidPlan()
		}
		seen[d.ContractID] = true
		switch d.Owner {
		case "identity/postgres":
			domains++
		case "audit/postgres":
			audits++
		default:
			return [32]byte{}, invalidPlan()
		}
		contributors[i] = cborMap(map[string][]byte{"owner": cborText(d.Owner), "contract_id": cborText(d.ContractID), "version": cborUint(uint64(d.Version))})
	}
	if domains != 1 || audits != 1 {
		return [32]byte{}, invalidPlan()
	}
	events := make([][]byte, len(plan.Audits))
	for i, p := range plan.Audits {
		events[i] = cborMap(map[string][]byte{
			"event_type": cborText(p.EventType), "schema_version": cborUint(uint64(p.SchemaVersion)),
			"event_index": cborUint(uint64(p.EventIndex)), "binding_digest": cborBytes(p.BindingDigest[:]),
			"retention_policy_version": cborUint(p.RetentionPolicyVersion), "required_record_count": cborUint(uint64(p.RequiredRecordCount)),
			"max_record_bytes": cborUint(uint64(p.MaxRecordBytes)), "max_aggregate_bytes": cborUint(uint64(p.MaxAggregateBytes)), "required": cborBool(p.Required),
		})
	}
	encoded := cborMap(map[string][]byte{"profile": cborText("identity-kernel-plan-v1"), "binding": cborMap(commandScope(binding)), "fingerprint": cborBytes(fingerprint[:]), "contributors": cborArray(contributors), "audits": cborArray(events)})
	return sha256.Sum256(encoded), nil
}

// admittedKernelPlan never escapes the coordinator boundary. It freezes only
// the supported kernel profile, not arbitrary callbacks or opaque input blobs.
type admittedKernelPlan struct {
	registry     *contributorRegistryState
	binding      identity.CommandBinding
	digest       [32]byte
	contributors []registeredContributor
	audits       []AuditPlan
}

func (r *ContributorRegistry) admitKernelPlan(binding identity.CommandBinding, fingerprint [32]byte, p CommandPlan) (*admittedKernelPlan, error) {
	digest, err := KernelPlanDigest(binding, fingerprint, p)
	if err != nil || digest != p.Digest {
		return nil, invalidPlan()
	}
	entries, err := r.selectContributors(p.Contributors)
	if err != nil {
		return nil, invalidPlan()
	}
	for _, entry := range entries {
		if entry.descriptor.Owner == "audit/postgres" {
			if _, ok := entry.contributor.(AuditContributor); !ok {
				return nil, invalidPlan()
			}
		}
	}
	return &admittedKernelPlan{registry: r.state, binding: binding, digest: digest, contributors: entries, audits: append([]AuditPlan(nil), p.Audits...)}, nil
}

func (p *admittedKernelPlan) belongsTo(r *ContributorRegistry) error {
	if p == nil || p.registry == nil || r == nil || r.state != p.registry {
		return invalidPlan()
	}
	return nil
}

func (p *admittedKernelPlan) bindWork(w Work) error {
	if err := w.usable(); err != nil {
		return err
	}
	if p == nil || p.registry == nil || p.registry != w.state.registry || p.binding != w.state.binding {
		return invalidPlan()
	}
	return bindAuditPlans(w, p.audits)
}

func invalidPlan() error { return identity.InvalidInputError{Field: "command_plan"} }
