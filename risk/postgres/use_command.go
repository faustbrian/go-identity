package postgres

import (
	"bytes"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// PrepareEvidenceUse maps an opaque core precheck and its exact trusted original
// scope into a consuming native phone-reset initiation command and signed plan.
// UseIssuer must be configured. The supplied feature spec must use the closed
// native phone schema and must not already contain risk.intent or risk.use.*.
// Other feature fields are preserved and remain the phone owner's responsibility.
// Raw phone, pre-auth, attempt and subject dimensions live only in the opaque
// in-memory command; neither the plan nor journal gains those values or a bearer.
// Inputs are copied, must not be concurrently mutated, and must never be logged.
// This pure bounded preparation samples no time and performs no callbacks/IO.
// It grants no current-counter, journal, reservation or domain authority; every
// failure returns zero outputs and redacted ErrInvalidEvidenceExecution.
func (r *Repository) PrepareEvidenceUse(spec identity.FeatureCommandSpec, original risk.PhoneEvidenceRequest, use risk.EvidenceUse) (identity.Command, identitypostgres.RiskEvidencePlan, error) {
	fail := func() (identity.Command, identitypostgres.RiskEvidencePlan, error) {
		return identity.Command{}, identitypostgres.RiskEvidencePlan{}, risk.ErrInvalidEvidenceExecution
	}
	if r == nil || r.useIssuer == nil || spec.Operation != nativeUseOperation() || len(spec.Fields) > 121 {
		return fail()
	}
	for _, f := range spec.Fields {
		if f.Name == "risk.intent" || strings.HasPrefix(f.Name, "risk.use.") {
			return fail()
		}
	}
	p := use.Prepared()
	// This is a historical structural check, not a new validity observation.
	// Rounding upward avoids granting a precheck earlier than its signed instant.
	if _, err := r.useIssuer.RecheckUse(original, p, useCheckTime(p.CheckedAt)); err != nil {
		return fail()
	}
	spec.Fields = append(append([]identity.FeatureField(nil), spec.Fields...),
		bytesField("risk.intent", p.Binding.IntentDigest),
		textField("risk.use.number", original.Recovery.Binding.CanonicalNumber),
		textField("risk.use.preauth", original.Recovery.Binding.PreAuthTransaction),
		textField("risk.use.attempt", original.Recovery.Binding.Attempt),
		textField("risk.use.network", original.Subject.Network),
		textField("risk.use.device", original.Subject.Device),
		textField("risk.use.identifier", original.Subject.IdentifierDigest))
	command, err := identity.NewFeatureCommand(spec)
	plan := evidenceUsePlan(p)
	if err != nil || r.ValidateRiskEvidenceCommand(command, plan) != nil {
		return fail()
	}
	return command, plan, nil
}

// ValidateRiskEvidenceCommand authenticates the complete native original intent
// and signed consuming plan under configured current policy/provider versions.
// Only phone-reset initiation is supported. Non-risk feature fields are checked
// separately by the phone owner, including equality with its domain target.
// Validation uses the original signed check instant rounded up to microseconds;
// it is not admission at current time. It performs no IO, clock or callbacks and
// cannot replace current authoritative row/counter/expiry checks or finalization.
// Zero, disabled, malformed or mismatched input returns one redacted error.
// This method alone does not implement or enable RiskExecutionContributor.
func (r *Repository) ValidateRiskEvidenceCommand(command identity.Command, plan identitypostgres.RiskEvidencePlan) error {
	if r == nil || r.useIssuer == nil {
		return risk.ErrInvalidEvidenceExecution
	}
	s, ok := command.Feature()
	if !ok || s.Operation != nativeUseOperation() {
		return risk.ErrInvalidEvidenceExecution
	}
	claim, err := r.restoreUse(identitypostgres.RiskReservationBinding{Command: s.Binding, Plan: plan})
	if err != nil {
		return risk.ErrInvalidEvidenceExecution
	}
	original := risk.PhoneEvidenceRequest{CommandID: plan.IssuanceCommandID, Actor: plan.IssuerActor,
		Recovery: risk.CarrierRequest{Phase: risk.IssuancePhase(plan.Phase), Binding: risk.PhoneRecoveryScope{Tenant: plan.Tenant, Subject: plan.Subject, RecoveryOperation: risk.Action(plan.RecoveryOperation), PolicyVersion: plan.PolicyVersion}}}
	found := 0
	for _, f := range s.Fields {
		if f.Name == "risk.intent" {
			if f.Value.Kind != identity.FeatureBytes || !bytes.Equal(f.Value.Bytes, plan.IntentDigest[:]) {
				return risk.ErrInvalidEvidenceExecution
			}
			found++
			continue
		}
		if !strings.HasPrefix(f.Name, "risk.use.") {
			continue
		}
		if f.Value.Kind != identity.FeatureText {
			return risk.ErrInvalidEvidenceExecution
		}
		switch f.Name {
		case "risk.use.number":
			original.Recovery.Binding.CanonicalNumber = f.Value.Text
		case "risk.use.preauth":
			original.Recovery.Binding.PreAuthTransaction = f.Value.Text
		case "risk.use.attempt":
			original.Recovery.Binding.Attempt = f.Value.Text
		case "risk.use.network":
			original.Subject.Network = f.Value.Text
		case "risk.use.device":
			original.Subject.Device = f.Value.Text
		case "risk.use.identifier":
			original.Subject.IdentifierDigest = f.Value.Text
		default:
			return risk.ErrInvalidEvidenceExecution
		}
		found++
	}
	if found != 7 {
		return risk.ErrInvalidEvidenceExecution
	}
	if _, err := r.useIssuer.RecheckUse(original, claim.Prepared(), useCheckTime(plan.CheckedAt)); err != nil {
		return risk.ErrInvalidEvidenceExecution
	}
	return nil
}

func nativeUseOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-request", SchemaID: "identity.phone.password-reset-request.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func useCheckTime(t time.Time) time.Time {
	if t.Nanosecond()%1000 != 0 {
		return t.Truncate(time.Microsecond).Add(time.Microsecond)
	}
	return t
}

func evidenceUsePlan(p risk.PreparedEvidenceUse) identitypostgres.RiskEvidencePlan {
	return identitypostgres.RiskEvidencePlan{IssuanceCommandID: p.Binding.CommandID, Tenant: p.Binding.Tenant, Subject: p.Binding.Subject, IssuerActor: p.Binding.Actor, Purpose: p.Binding.Purpose, Phase: string(p.Binding.Phase), RecoveryOperation: string(p.Binding.RecoveryOperation), PolicyVersion: p.Binding.PolicyVersion, KeyVersion: p.Binding.KeyVersion, IntentDigest: p.Binding.IntentDigest, ConsumerCommandID: p.ConsumerCommandID, ConsumerActor: p.ConsumerActor, EvidenceDigest: p.EvidenceDigest, ProofDigest: p.ProofDigest, Signature: p.Signature, IssuedAt: p.IssuedAt, CheckedAt: p.CheckedAt, ExpiresAt: p.ExpiresAt}
}
