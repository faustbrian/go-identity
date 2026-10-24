package risk

import (
	"crypto/hmac"
	"time"
)

// PreparePasskeySignup derives protected counters for exactly the two canonical
// passkey registration actions. The native signup owner must authenticate the
// original browserFlowID and trusted Network/Device; no user or session exists
// yet. Only Network and Device may be present in subject. Pure preparation is
// neither browser authentication nor allowance, mutation or durable reservation.
//
// The canonical CredentialMutation policy retains every numerical limit,
// mandatory signal, deny/unknown outcome and ReserveWithCommand phase. Only
// dimensions change to tenant/original-browser-flow/network/device. A new
// attempt cannot reset those buckets. The owning PostgreSQL participant must
// charge once with its protected command and preserve original primaryTime.
// Calls are bounded/concurrent-safe, perform no IO and own no resources.
func (p CommandCounterPolicy) PreparePasskeySignup(scope Context, subject Subject, browserFlowID string, primaryTime time.Time) (CounterCommand, error) {
	if p.state == nil {
		return CounterCommand{}, ErrInvalidPolicy
	}
	if scope.Operation != "identity.passkey.register-options" && scope.Operation != "identity.passkey.register-verify" || !databaseEvidenceTime(primaryTime) || !scopeID(scope.Tenant) || !scopeID(scope.Attempt) || !verificationCounterID(browserFlowID) {
		return CounterCommand{}, ErrInvalidCounterCommand
	}
	a, err := p.state.policy.Admit(scope.Operation)
	if err != nil || a.Preflight != "" || a.Profile.Class != CredentialMutation || a.Profile.Phase != ReserveWithCommand {
		return CounterCommand{}, ErrUnsupportedCounterPhase
	}
	values, err := counterDimensions(subject, scope.Tenant, []Dimension{TenantDimension, NetworkDimension, DeviceDimension})
	if err != nil {
		return CounterCommand{}, err
	}
	values[BrowserFlowDimension] = browserFlowID
	a.Profile.Dimensions = []Dimension{TenantDimension, BrowserFlowDimension, NetworkDimension, DeviceDimension}
	command := prepareCounterValues(scope, values, ReserveWithCommand, a, primaryTime, p.state.keys, true)
	command.state.commandOwner = p.state
	return command, nil
}

// ValidatePasskeySignup authenticates this policy's exact original preparation,
// scope/dimensions and exclusive lifetime at trusted database time. It cannot
// renew PreparedAt, charge counters, authenticate browser custody or substitute
// for the owning transaction's authority/current-key-history checks.
func (p CommandCounterPolicy) ValidatePasskeySignup(command CounterCommand, scope Context, subject Subject, browserFlowID string, primaryTime time.Time) error {
	if p.state == nil || command.state == nil || command.state.owner != nil || command.state.commandOwner != p.state || !databaseEvidenceTime(primaryTime) {
		return ErrInvalidCounterCommand
	}
	b := command.state.binding
	if primaryTime.Before(b.PreparedAt) || !primaryTime.Before(b.PreparedAt.Add(command.state.profile.EvidenceTTL)) {
		return ErrInvalidCounterCommand
	}
	expected, err := p.PreparePasskeySignup(scope, subject, browserFlowID, b.PreparedAt)
	if err != nil || !hmac.Equal([]byte(expected.state.binding.Fingerprint), []byte(b.Fingerprint)) {
		return ErrInvalidCounterCommand
	}
	return nil
}
