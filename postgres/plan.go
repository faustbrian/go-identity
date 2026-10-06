package postgres

import (
	"crypto/sha256"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

// CommandPlan is the complete declaration supplied by a PostgreSQL composition
// adapter before reservation. Contributors are ordered exact registry entries;
// Audits declare mandatory event slots, and Digest binds this declaration to
// the exact command and its authoritative retained-key fingerprint. Callers
// must not mutate its slices during admission. Admission owns copies, so later
// changes do not affect execution. Zero is invalid. This value conveys no
// transaction authority. Typed Capability input can be frozen and inspected,
// but its execution phases remain under development; no one-time contributor
// can be admitted by name or declaration alone.
// Lifecycle, when present, requires the typed outbox contributor and declares
// the successful mutation notification. Nil preserves the older audit-only
// admission profile; it is not sufficient for a future successful mutation
// commit, which must require its lifecycle and full effect declarations.
type CommandPlan struct {
	// IdentifierAdmission selects an exact read-only session checker, not a
	// durable effect participant. Nil preserves historical plan bytes. Public
	// identifier execution remains disabled until native composition is complete.
	IdentifierAdmission *ContributorDescriptor
	Contributors        []ContributorDescriptor
	Audits              []AuditPlan
	Lifecycle           *LifecyclePlan
	// Delivery enlists encrypted effects under this original command, never
	// an independently committable enqueue operation. Nil leaves bytes unchanged.
	Delivery *DeliveryPlan
	// CapabilityIssuance declares original-command production, independently
	// from consuming an existing one-use capability. Nil preserves history.
	CapabilityIssuance *CapabilityIssuancePlan
	// Capability declares a typed one-use participant input. Identifier reservation
	// requires its registered reservation contributor; domain execution is disabled.
	Capability *CapabilityPlan
	// RiskEvidence freezes a signed reset-initiation precheck. The exact registered
	// risk reservation participant is required; domain execution remains disabled.
	RiskEvidence *RiskEvidencePlan
	// CaptchaEvidence declares consuming custody, not issuance replay. It shares
	// the exact risk owner with counters/phone evidence where declared. Preparation
	// and reservation require its typed native validation/reservation contributor.
	// Domain execution and pending release/recovery remain closed until their
	// current-check, finalization and proof-bound release phases are complete.
	CaptchaEvidence *CaptchaEvidencePlan
	// CommandCounters declares protected-command durable counter admission.
	// It requires the exact native risk participant; no raw dimensions are stored.
	CommandCounters *CommandCounterPlan
	// CaptchaReplayReservation declares the native CAPTCHA issuance participant's
	// durable alias reservation/rebind before domain work. False preserves old
	// plan bytes. Only the exact CAPTCHA issuance schemas admit this phase; the
	// immutable command carries its signed original aliases and configuration.
	CaptchaReplayReservation bool
	// Feature declares one exact registered feature schema. Kernel digests reject
	// it; native execution additionally requires SubjectType and typed phases.
	Feature *FeatureRegistration
	// SubjectType fixes the feature audit/lifecycle primary target kind. Empty
	// retains the historical structural-only v1 profile; native execution needs
	// a canonical lowercase audit kind and the registered typed feature phases.
	// Kernel plans reject it. It is copied and bound in the v2 feature digest.
	SubjectType string
	Digest      [32]byte
}

// KernelPlanDigest returns a domain-separated SHA-256 digest of the current
// kernel-only plan, command binding and nonzero authoritative fingerprint.
// It uses deterministic CBOR and preserves contributor order and every audit
// field. Digest itself is excluded. This is binding, not authentication or
// proof that the fingerprint is authoritative: the sole coordinator must
// resolve retained fingerprint keys and compute it from the typed command.
// Exactly one identity/postgres and one audit/postgres contributor are required;
// a lifecycle declaration additionally requires exactly one outbox/postgres
// identity.lifecycle v1 contributor. A capability declaration requires lifecycle
// plus exactly one capability.one-use v1 contributor. Existing audit-only and
// lifecycle digest bytes remain unchanged. Digest preparation does not activate
// that participant: reservation additionally requires the typed contributor;
// domain execution remains disabled until its remaining phases exist.
// Feature/one-time contributors without typed inputs are rejected, not
// silently omitted. Invalid inputs return redacted identity.InvalidInputError. It does
// no I/O or callbacks. Concurrent calls require immutable caller-owned inputs.
func KernelPlanDigest(binding identity.CommandBinding, fingerprint [32]byte, plan CommandPlan) ([32]byte, error) {
	encoded, err := encodeKernelPlan(binding, fingerprint, plan)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

// The journal freezes the exact digest input, not a second serialization that
// can disagree with admission or omit a participant field.
func encodeKernelPlan(binding identity.CommandBinding, fingerprint [32]byte, plan CommandPlan) ([]byte, error) {
	if plan.Delivery != nil {
		return encodeDeliveryWrappedPlan(binding, fingerprint, plan, encodeKernelPlan)
	}
	if plan.CapabilityIssuance != nil {
		return encodeIssuanceWrappedPlan(binding, fingerprint, plan, encodeKernelPlan)
	}
	if plan.Feature != nil || plan.SubjectType != "" || plan.RiskEvidence != nil || plan.CaptchaEvidence != nil || plan.CommandCounters != nil || plan.CaptchaReplayReservation {
		return nil, invalidPlan()
	}
	probe := identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeInProgress, RetryAfter: time.Microsecond}
	count := 2
	if plan.Lifecycle != nil {
		count++
	}
	if plan.Capability != nil {
		count++
		if plan.Lifecycle == nil {
			return nil, invalidPlan()
		}
	}
	if probe.Validate() != nil || fingerprint == ([32]byte{}) || len(plan.Contributors) != count || validateKernelAuditPlans(binding, plan.Audits) != nil || validateLifecyclePlan(binding, plan.Lifecycle) != nil || validateCapabilityPlan(binding, plan.Capability) != nil {
		return nil, invalidPlan()
	}
	domains, audits, lifecycles, capabilities := 0, 0, 0, 0
	contributors := make([][]byte, len(plan.Contributors))
	seen := make(map[string]bool, len(plan.Contributors))
	for i, d := range plan.Contributors {
		if !validContributorDescriptor(d) || seen[d.ContractID] {
			return nil, invalidPlan()
		}
		seen[d.ContractID] = true
		switch d.Owner {
		case "identity/postgres":
			domains++
		case "audit/postgres":
			audits++
		case "outbox/postgres":
			if plan.Lifecycle == nil || d.ContractID != "identity.lifecycle" || d.Version != 1 {
				return nil, invalidPlan()
			}
			lifecycles++
		case "capability/postgres":
			if plan.Capability == nil || d.ContractID != "capability.one-use" || d.Version != 1 {
				return nil, invalidPlan()
			}
			capabilities++
		default:
			return nil, invalidPlan()
		}
		contributors[i] = cborMap(map[string][]byte{"owner": cborText(d.Owner), "contract_id": cborText(d.ContractID), "version": cborUint(uint64(d.Version))})
	}
	if domains != 1 || audits != 1 || plan.Lifecycle != nil && lifecycles != 1 || plan.Capability != nil && capabilities != 1 {
		return nil, invalidPlan()
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
	fields := map[string][]byte{"profile": cborText("identity-kernel-plan-v1"), "binding": cborMap(commandScope(binding)), "fingerprint": cborBytes(fingerprint[:]), "contributors": cborArray(contributors), "audits": cborArray(events)}
	if p := plan.Lifecycle; p != nil {
		fields["lifecycle"] = cborMap(map[string][]byte{"event_type": cborText(p.EventType), "event_index": cborUint(uint64(p.EventIndex)), "before_version": cborUint(p.BeforeVersion), "after_version": cborUint(p.AfterVersion)})
	}
	if plan.Capability != nil {
		fields["capability"] = encodeCapabilityPlan(plan.Capability)
	}
	if d := plan.IdentifierAdmission; d != nil {
		if plan.Capability == nil || *d != identifierAdmissionDescriptor() {
			return nil, invalidPlan()
		}
		fields["identifier_admission"] = cborMap(map[string][]byte{"owner": cborText(d.Owner), "contract_id": cborText(d.ContractID), "version": cborUint(uint64(d.Version))})
	}
	return cborMap(fields), nil
}

// admittedKernelPlan never escapes the coordinator boundary. It freezes only
// the supported kernel profile, not arbitrary callbacks or opaque input blobs.
type admittedKernelPlan struct {
	identifierAdmission *registeredContributor
	registry            *contributorRegistryState
	binding             identity.CommandBinding
	digest              [32]byte
	contributors        []registeredContributor
	audits              []AuditPlan
	lifecycle           *LifecyclePlan
	capability          *CapabilityPlan
	risk                *RiskEvidencePlan
	counters            *CommandCounterPlan
	captchaReplay       bool
	captchaUse          *CaptchaEvidencePlan
	fingerprint         [32]byte
	feature             *FeatureRegistration
	subjectType         string
	delivery            *DeliveryPlan
	issuance            *CapabilityIssuancePlan
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
	if validateDeliveryContributor(binding, p.Delivery, entries) != nil {
		return nil, invalidPlan()
	}
	if validateIssuanceContributor(binding, p.CapabilityIssuance, entries) != nil {
		return nil, invalidPlan()
	}
	for _, entry := range entries {
		if entry.descriptor.Owner == "audit/postgres" {
			if _, ok := entry.contributor.(AuditContributor); !ok {
				return nil, invalidPlan()
			}
		}
		if entry.descriptor.Owner == "outbox/postgres" {
			if _, ok := entry.contributor.(LifecycleContributor); !ok {
				return nil, invalidPlan()
			}
		}
		if entry.descriptor.Owner == "capability/postgres" && entry.descriptor.ContractID == "capability.one-use" {
			if _, ok := capabilityReservationParticipant(entry.contributor); !ok {
				return nil, invalidPlan()
			}
		}
	}
	var lifecycle *LifecyclePlan
	var checker *registeredContributor
	if p.IdentifierAdmission != nil {
		selected, err := r.selectContributors([]ContributorDescriptor{*p.IdentifierAdmission})
		if err != nil || len(selected) != 1 {
			return nil, invalidPlan()
		}
		participant, ok := selected[0].contributor.(IdentifierAdmissionContributor)
		if !ok || nilContributor(participant) || !sameParticipant(participant, participant) {
			return nil, invalidPlan()
		}
		checker = &selected[0]
	}
	if p.Lifecycle != nil {
		snapshot := *p.Lifecycle
		lifecycle = &snapshot
	}
	var capability *CapabilityPlan
	if p.Capability != nil {
		snapshot := *p.Capability
		capability = &snapshot
	}
	return &admittedKernelPlan{identifierAdmission: checker, registry: r.state, binding: binding, digest: digest, contributors: entries, audits: append([]AuditPlan(nil), p.Audits...), lifecycle: lifecycle, capability: capability, fingerprint: fingerprint, delivery: cloneDeliveryPlan(p.Delivery), issuance: cloneCapabilityIssuancePlan(p.CapabilityIssuance)}, nil
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
	w.state.feature, w.state.subjectType = p.feature, p.subjectType
	if p.issuance != nil {
		w.state.issuance = &workIssuance{plan: cloneCapabilityIssuancePlan(p.issuance), grants: make([]capability.Grant, len(p.issuance.Grants)), staged: make([]bool, len(p.issuance.Grants))}
	}
	if p.delivery != nil {
		w.state.delivery = &workDelivery{plan: cloneDeliveryPlan(p.delivery), envelopes: make(map[uint16]DeliveryEnvelope)}
	}
	if err := bindAuditPlans(w, p.audits); err != nil {
		return err
	}
	if p.lifecycle != nil {
		if err := bindLifecyclePlan(w, p.lifecycle); err != nil {
			return w.fail(w.state.ctx, err)
		}
	}
	return nil
}

func invalidPlan() error { return identity.InvalidInputError{Field: "command_plan"} }
