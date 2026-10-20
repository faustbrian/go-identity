package postgres

// OTPConsumption exposes the original checked consuming reservation only to
// the exact feature owner during its protected ApplyFeature invocation. This
// lets a session-owned effect bind its writes to OTP admission in the SAME
// transaction, without accepting a caller-created success flag or committing
// authentication separately. Non-consuming checks, unchecked reservations,
// recovery, foreign owners and returned/failed/closed handles fail closed.
//
// The returned scalar copy contains no code or bearer and grants no independent
// authority. The OTP owner remains responsible for purpose, possession, current
// eligibility and finalization; the feature owner must bind its complete effect
// to the original command and reservation. Commit may still fail, so this is
// neither a completed authentication proof nor permission to deliver a token.
// Calls are serial within the callback; no IO, comparison or mutation occurs.
func (w Work) OTPConsumption(owner FeatureExecutionContributor) (OTPReservationBinding, error) {
	if _, _, _, err := w.FeatureScope(owner); err != nil {
		return OTPReservationBinding{}, err
	}
	s := w.state
	if !s.featureApplying || s.otpCommand == nil || s.execution == nil || s.execution.reservation == nil || s.execution.reservation.plan == nil || s.generation == 0 {
		return OTPReservationBinding{}, invalidWork()
	}
	p := s.execution.reservation.plan
	if p.otp == nil || p.otp.Mode != OTPConsume || p.binding != s.binding || p.fingerprint == ([32]byte{}) {
		return OTPReservationBinding{}, invalidWork()
	}
	spec, ok := s.otpCommand.Feature()
	if !ok && phoneResetConsumptionPlan(p.snapshot()) {
		spec, ok = s.otpCommand.PhonePasswordResetFeature()
	}
	if !ok || spec.Binding != p.binding || spec.Operation != p.feature.Operation {
		return OTPReservationBinding{}, invalidWork()
	}
	return OTPReservationBinding{Command: p.binding, Plan: *p.otp, Fingerprint: p.fingerprint, Generation: s.generation}, nil
}
