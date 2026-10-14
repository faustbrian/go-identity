package risk

import "time"

// BrowserFlowDimension identifies the original unauthenticated browser flow,
// not an authenticated session, device, bearer or MFA child. Storage projections
// contain only tenant/action-scoped keyed digests. This distinct dimension
// prevents issuing another child in the same browser from resetting its budget.
const BrowserFlowDimension Dimension = "browser-flow"

// PrepareMFALoginSend prepares counters only for identity.mfa.otp-send. The
// native MFA owner must authenticate subject.User and browserFlowID against the
// original signed continuation and consumed-primary browser before reservation.
// Subject accepts only the resolved User and trusted Network; no session is
// invented. These structural inputs do not grant authentication or allowance.
//
// Preserve the canonical protected credential-mutation phase, limits, windows,
// signals and failure policy, replacing only the session dimension with the
// original browser flow. Tenant/account/network budgets span browser flows;
// browser protection spans newly issued children and send commands. The native
// adapter owns transactional charge/replay and must recheck current authority.
// Calls are pure, bounded and concurrent-safe, never sample a clock, retain
// caller-owned input, mutate counters or renew primaryTime. Errors return zero.
func (p CommandCounterPolicy) PrepareMFALoginSend(scope Context, subject Subject, browserFlowID string, primaryTime time.Time) (CounterCommand, error) {
	return p.prepareBoundCounter(scope, subject, browserFlowID, BrowserFlowDimension, primaryTime, "identity.mfa.otp-send")
}

// ValidateMFALoginSend authenticates exact policy ownership, original tenant,
// action, command, subject, network and browser-flow projection at supplied
// primary time. Original evidence expiry is exclusive and is never renewed.
// Session-based, child-based and foreign commands deny. This pure check grants
// no child/factor authority or durable allowance; the registered native owner
// still validates original source custody and authoritative counter rows.
func (p CommandCounterPolicy) ValidateMFALoginSend(command CounterCommand, scope Context, subject Subject, browserFlowID string, primaryTime time.Time) error {
	return p.validateBoundCounter(command, scope, subject, browserFlowID, BrowserFlowDimension, primaryTime, "identity.mfa.otp-send")
}
