package postgres

import "github.com/faustbrian/go-identity/risk"

// ValidateCounterOnlyOperation checks that this repository's actual immutable
// counter policy requires only the velocity signal for the selected protected
// operation. A workflow without provider-evidence admission must call this at
// composition so configured status/CAPTCHA facts cannot be silently omitted.
// It grants no allowance, authentication or mutation permission and performs no
// IO. Nil, disabled, unlisted, non-protected or richer configurations return
// risk.ErrInvalidPolicy. Concurrent calls are safe under the repository's
// immutable configuration contract; the supplied operation is not retained.
func (r *Repository) ValidateCounterOnlyOperation(operation risk.Action) error {
	if r == nil || r.counters == nil {
		return risk.ErrInvalidPolicy
	}
	admission, err := r.counters.Policy.Admit(operation)
	if err != nil || admission.PolicyVersion != r.policy || admission.Preflight != "" || admission.Profile.Phase != risk.ReserveWithCommand || admission.Profile.Class != risk.CredentialMutation && admission.Profile.Class != risk.Privileged || len(admission.Profile.RequiredSignals) != 1 || admission.Profile.RequiredSignals[0] != "velocity" {
		return risk.ErrInvalidPolicy
	}
	return nil
}
