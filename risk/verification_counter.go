package risk

import (
	"crypto/hmac"
	"time"
)

// CapabilityDimension identifies an authenticated original one-use grant, not
// an authenticated session or bearer. Its value is a bounded stable grant ID,
// never the proof bytes; only a tenant/action-scoped keyed digest is projected.
const CapabilityDimension Dimension = "capability"

// PrepareVerification prepares the sessionless registration-link counter lane
// for exactly identity.email.verification-confirm. The workflow must obtain
// capabilityID and subject.User from its authenticated original signed grant,
// and subject.Network from trusted transport policy. ID structure alone grants
// no authentication, allowance, current authority or permission to consume.
// All Subject fields other than User and Network must be empty.
//
// The canonical CredentialMutation policy supplies every existing limit,
// window, failure policy, mandatory signal and evidence lifetime. The closed
// registration-verification profile replaces only its session dimension with
// the capability dimension: tenant and subject limits still apply across links.
// Normal Prepare and all other operations retain their session requirements.
// The original UTC microsecond primaryTime is never refreshed. Calls are pure,
// concurrent-safe, bounded and own no resources; every error returns zero.
func (p CommandCounterPolicy) PrepareVerification(scope Context, subject Subject, capabilityID string, primaryTime time.Time) (CounterCommand, error) {
	if p.state == nil {
		return CounterCommand{}, ErrInvalidPolicy
	}
	if scope.Operation != "identity.email.verification-confirm" || !databaseEvidenceTime(primaryTime) || !scopeID(scope.Tenant) || !scopeID(scope.Attempt) || !verificationCounterID(capabilityID) {
		return CounterCommand{}, ErrInvalidCounterCommand
	}
	a, err := p.state.policy.Admit(scope.Operation)
	if err != nil {
		return CounterCommand{}, err
	}
	if a.Preflight != "" || a.Profile.Class != CredentialMutation || a.Profile.Phase != ReserveWithCommand {
		return CounterCommand{}, ErrUnsupportedCounterPhase
	}
	values, err := counterDimensions(subject, scope.Tenant, []Dimension{TenantDimension, SubjectDimension, NetworkDimension})
	if err != nil {
		return CounterCommand{}, err
	}
	values[CapabilityDimension] = capabilityID
	a.Profile.Dimensions = []Dimension{TenantDimension, SubjectDimension, CapabilityDimension, NetworkDimension}
	command := prepareCounterValues(scope, values, ReserveWithCommand, a, primaryTime, p.state.keys, true)
	command.state.commandOwner = p.state
	return command, nil
}

// ValidateVerification authenticates this policy's exact original proof-bound
// preparation and its exclusive evidence lifetime at supplied primary time.
// It never authenticates the proof, renews PreparedAt or samples a clock.
// Changed tenant/action/attempt/user/network/grant, foreign policy ownership,
// session-based commands and expired evidence deny. The native participant
// still owns current row/key-history checks and transactional allowance.
func (p CommandCounterPolicy) ValidateVerification(command CounterCommand, scope Context, subject Subject, capabilityID string, primaryTime time.Time) error {
	if p.state == nil || command.state == nil || command.state.owner != nil || command.state.commandOwner != p.state || !databaseEvidenceTime(primaryTime) {
		return ErrInvalidCounterCommand
	}
	b := command.state.binding
	if primaryTime.Before(b.PreparedAt) || !primaryTime.Before(b.PreparedAt.Add(command.state.profile.EvidenceTTL)) {
		return ErrInvalidCounterCommand
	}
	expected, err := p.PrepareVerification(scope, subject, capabilityID, b.PreparedAt)
	if err != nil || !hmac.Equal([]byte(expected.state.binding.Fingerprint), []byte(b.Fingerprint)) {
		return ErrInvalidCounterCommand
	}
	return nil
}

func verificationCounterID(id string) bool {
	if len(id) == 0 || len(id) > 256 {
		return false
	}
	for _, b := range []byte(id) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
