package reference

import (
	"fmt"
	"io"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/email"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// EmailConfiguration selects native email capabilities, not HTTP. Nil entries
// expose no handle or feature. Management uses the selected password verification
// owner's original proof/session authority; address reads use the graph's
// authorization and disclosure policy. Removal requires actual selected password
// signin/reset owners. No UI or auto-signin is enabled.
type EmailConfiguration struct {
	Verification    *EmailManagementConfiguration
	Change          *EmailManagementConfiguration
	Addresses       *EmailAddressConfiguration
	Removal         *EmailRemovalConfiguration
	OTPVerification *EmailOTPVerificationConfiguration
	OTPChange       *EmailOTPChangeConfiguration
}

// EmailRemovalConfiguration selects protected native self-removal without HTTP.
// Primary.Action/CSRFKeys and Native counters/provider evaluator/keys/policy must
// be absent; the graph supplies those actual owners. Both password signin and
// emailed reset request/completion must be selected. Native.Domain defines the
// explicit primary/recovery, reuse and pending lifecycle admission policy.
// Borrowed configuration callbacks/resources must remain concurrency-safe.
type EmailRemovalConfiguration struct {
	Native   passwordpg.EmailRemovalConfig
	Primary  passwordpg.EmailPrimaryConfig
	Counters riskpg.Config
}

// EmailManagementConfiguration selects one delivered-link native workflow.
// Primary.Action and Primary.CSRFKeys must be absent: the selected slot fixes
// action, and cookie mode borrows the graph's actual verification synchronizer.
// Primary audience/age/transport must be explicit and its exact target must be
// allowed by PasswordVerification. Native counters/evaluator/evidence keys,
// counter policy and delivery renderer/owner must be absent; this graph supplies
// those owners. Counters uses the existing risk namespace and policy revision.
// Change notification renderer, when selected, also comes from graph templates.
// Configuration callbacks/resources are borrowed, bounded and concurrency-safe.
type EmailManagementConfiguration struct {
	Native   passwordpg.EmailManagementConfig
	Primary  passwordpg.EmailPrimaryConfig
	Counters riskpg.Config
	// Keyed optionally enables original-input correlation on the same native
	// journal. Nil exposes no keyed calls; unkeyed native calls stay unchanged.
	// Request-key policy must use the graph's current query-policy revision.
	Keyed *passwordpg.KeyedEmailManagementConfig
}

// EmailAddressConfiguration selects authorized primary list/get. Native.Clock
// must be absent: the actual session authority supplies it. Canonical-ID and
// disclosure callbacks are explicit bounded application policy, not stores or
// browser authority. The graph supplies the primary repository and authorizer.
type EmailAddressConfiguration struct {
	Native identity.UserQueryConfig
	Redact identity.RedactFunc
	// AdministrativeAudit explicitly selects required access auditing through
	// the existing native PostgreSQL audit owner, not another domain store.
	AdministrativeAudit *EmailAddressAuditConfiguration
}

// EmailAddressAuditConfiguration bounds required administrative acknowledgements
// within the query deadline. No retries, detached writes or fail-open fallback
// are selected. The graph borrows its existing PostgreSQL pool.
type EmailAddressAuditConfiguration struct{ MaximumDuration time.Duration }

type emailState struct {
	verification, change                 *passwordpg.EmailManagementService
	addresses                            *email.AddressQueryService
	confirmation                         *passwordpg.EmailVerificationRouter
	keyedVerification, keyedChange       *passwordpg.KeyedEmailManagementService
	verificationRequests, changeRequests *passwordpg.EmailRequestWorkflow
	removal                              *passwordpg.EmailRemovalService
	otpVerification                      *otppg.EmailVerificationService
	otpChange                            *otppg.EmailChangeService
}

func validateEmailSelection(c StoreConfiguration) error {
	if c.Email == nil {
		return nil
	}
	e := c.Email
	invalid := identity.InvalidInputError{Field: "reference_email"}
	if e.Verification == nil && e.Change == nil && e.Addresses == nil && e.Removal == nil && e.OTPVerification == nil && e.OTPChange == nil || c.Session == nil || c.OTP == nil {
		return invalid
	}
	if (e.Verification != nil || e.Change != nil) && (c.PasswordVerification == nil || c.Delivery == nil) {
		return invalid
	}
	if e.Removal != nil && (c.PasswordVerification == nil || c.PasswordSignin == nil || c.PasswordReset == nil) {
		return invalid
	}
	if e.OTPChange != nil && (e.Change == nil || e.Change.Native.ChangeNotification == nil || c.PasswordSignin == nil || c.Delivery == nil) {
		return invalid
	}
	return nil
}

func composeEmail(c StoreConfiguration, d ReferenceDependencies, evaluation risk.Evaluator, proof *passwordVerificationState, signin *passwordpg.SigninService, reset *passwordpg.ResetService) (*emailState, error) {
	if c.Email == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_email"}
	if validateEmailSelection(c) != nil || d.PostgreSQL == nil || c.Session.Native.Execution.Clock == nil {
		return nil, invalid
	}
	state := &emailState{}
	if c.Email.Addresses != nil {
		a := *c.Email.Addresses
		if a.Native.Clock != nil || a.Native.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion || a.Native.MaximumDuration > c.OTP.Timeout {
			return nil, invalid
		}
		repository, err := kernel.NewRepository(d.PostgreSQL, kernel.Config{MaximumDuration: a.Native.MaximumDuration})
		if err != nil {
			return nil, invalid
		}
		a.Native.Clock = c.Session.Native.Execution.Clock
		if a.AdministrativeAudit != nil {
			sink, e := auditpg.New(d.PostgreSQL.Raw(), auditpg.Config{})
			if e != nil {
				return nil, invalid
			}
			state.addresses, err = email.NewAuditedAddressQueryService(repository, c.OTP.RequestKeys.Policy.Authorization, a.Redact, a.Native, email.AdministrativeReadAuditConfig{Sink: sink, MaximumDuration: a.AdministrativeAudit.MaximumDuration})
		} else {
			state.addresses, err = email.NewAddressQueryService(repository, c.OTP.RequestKeys.Policy.Authorization, a.Redact, a.Native)
		}
		if err != nil {
			return nil, invalid
		}
	}
	var err error
	state.verification, err = composeManagedEmail(c, d, evaluation, proof, c.Email.Verification, "identity.email.verification-send")
	if err != nil {
		return nil, err
	}
	state.change, err = composeManagedEmail(c, d, evaluation, proof, c.Email.Change, "identity.email.change-request")
	if err != nil {
		return nil, err
	}
	state.removal, err = composeEmailRemoval(c, d, evaluation, proof, signin, reset)
	if err != nil {
		return nil, err
	}
	for _, slot := range []struct {
		selected *EmailManagementConfiguration
		native   *passwordpg.EmailManagementService
		target   **passwordpg.KeyedEmailManagementService
	}{{c.Email.Verification, state.verification, &state.keyedVerification}, {c.Email.Change, state.change, &state.keyedChange}} {
		if slot.selected == nil || slot.selected.Keyed == nil {
			continue
		}
		if slot.selected.Keyed.RequestKeys.Policy.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion {
			return nil, invalid
		}
		*slot.target, err = passwordpg.NewKeyedEmailManagementService(slot.native, *slot.selected.Keyed)
		if err != nil {
			return nil, identity.InvalidInputError{Field: "reference_email_keyed"}
		}
	}
	for _, slot := range []struct {
		native *passwordpg.KeyedEmailManagementService
		target **passwordpg.EmailRequestWorkflow
	}{{state.keyedVerification, &state.verificationRequests}, {state.keyedChange, &state.changeRequests}} {
		if slot.native != nil {
			*slot.target, err = passwordpg.NewEmailRequestWorkflow(slot.native)
			if err != nil {
				return nil, identity.InvalidInputError{Field: "reference_email_keyed"}
			}
		}
	}
	return state, nil
}

func composeEmailRemoval(c StoreConfiguration, d ReferenceDependencies, evaluation risk.Evaluator, proof *passwordVerificationState, signin *passwordpg.SigninService, reset *passwordpg.ResetService) (*passwordpg.EmailRemovalService, error) {
	if c.Email.Removal == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_email_removal"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || proof == nil || proof.native == nil || signin == nil || reset == nil {
		return nil, invalid
	}
	selected := c.Email.Removal
	p, n := selected.Primary, selected.Native
	if p.Action != "" || len(p.CSRFKeys) != 0 || n.Counters != nil || n.Risk.Evaluation != (risk.Evaluator{}) || len(n.Risk.Keys) != 0 || n.CounterPolicy != (risk.Policy{}) || n.MaximumDuration > c.OTP.Timeout || selected.Counters.Schema != c.Velocity.Schema || selected.Counters.CommandCounters == nil || selected.Counters.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion || n.Keyed.RequestKeys.Policy.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion {
		return nil, invalid
	}
	p.Action = "identity.email.address-remove"
	if p.Transport == session.CredentialCookie {
		p.CSRFKeys = slices.Clone(c.PasswordVerification.CSRFKeys)
	}
	primary, err := passwordpg.NewEmailPrimarySource(proof.native, p)
	if err != nil {
		return nil, invalid
	}
	counters, err := riskpg.NewRepository(selected.Counters)
	if err != nil {
		return nil, invalid
	}
	n.Counters, n.CounterPolicy = counters, selected.Counters.CommandCounters.Policy
	n.Risk.Evaluation, n.Risk.Keys = evaluation, slices.Clone(c.OTP.RiskKeys)
	native, err := passwordpg.NewEmailRemovalService(primary, signin, reset, n, keys)
	if err != nil {
		return nil, invalid
	}
	return native, nil
}

func composeManagedEmail(c StoreConfiguration, d ReferenceDependencies, evaluation risk.Evaluator, proof *passwordVerificationState, selected *EmailManagementConfiguration, action string) (*passwordpg.EmailManagementService, error) {
	if selected == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_email_management"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || proof == nil || proof.native == nil || c.PasswordVerification == nil || c.Delivery == nil {
		return nil, invalid
	}
	p, n := selected.Primary, selected.Native
	if p.Action != "" || len(p.CSRFKeys) != 0 || n.Counters != nil || n.Risk.Evaluation != (risk.Evaluator{}) || len(n.Risk.Keys) != 0 || n.CounterPolicy != (risk.Policy{}) || n.Delivery.Owner != nil || n.Delivery.Renderer != nil || n.MaximumDuration > c.OTP.Timeout || n.Delivery.ProviderVersion != c.OTP.ProviderVersion || selected.Counters.Schema != c.Velocity.Schema || selected.Counters.CommandCounters == nil || selected.Counters.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion {
		return nil, invalid
	}
	p.Action = action
	if p.Transport == session.CredentialCookie {
		p.CSRFKeys = slices.Clone(c.PasswordVerification.CSRFKeys)
	}
	primary, err := passwordpg.NewEmailPrimarySource(proof.native, p)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_email_primary"}
	}
	counters, err := riskpg.NewRepository(selected.Counters)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_email_counters"}
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, invalid
	}
	owner, err := deliverypg.NewContributor(c.Delivery.Enqueue.Custody, crypto)
	if err != nil {
		return nil, invalid
	}
	renderer, err := delivery.NewTemplateRenderer(c.Delivery.Templates)
	if err != nil {
		return nil, invalid
	}
	if n.ChangeNotification != nil {
		if n.ChangeNotification.Renderer != nil {
			return nil, invalid
		}
		notice := *n.ChangeNotification
		notice.Renderer = renderer
		n.ChangeNotification = &notice
	}
	n.Delivery.Owner, n.Delivery.Renderer = owner, renderer
	n.Counters, n.CounterPolicy = counters, selected.Counters.CommandCounters.Policy
	n.Risk.Evaluation, n.Risk.Keys = evaluation, slices.Clone(c.OTP.RiskKeys)
	native, err := passwordpg.NewEmailManagementService(primary, n, keys)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_email_workflow"}
	}
	return native, nil
}

// Format redacts borrowed native policy and key custody.
func (EmailConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.EmailConfiguration(redacted)")
}

// MarshalJSON denies implicit configuration export.
func (EmailConfiguration) MarshalJSON() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// MarshalText denies implicit text export.
func (EmailConfiguration) MarshalText() ([]byte, error) { return nil, email.ErrSensitiveSerialization }

// Format redacts borrowed native proof, risk and delivery configuration.
func (EmailManagementConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.EmailManagementConfiguration(redacted)")
}

// MarshalJSON denies implicit native configuration export.
func (EmailManagementConfiguration) MarshalJSON() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}

// MarshalText denies implicit native text export.
func (EmailManagementConfiguration) MarshalText() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}

// Format redacts application disclosure and canonical-ID callbacks.
func (EmailAddressConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.EmailAddressConfiguration(redacted)")
}

// MarshalJSON denies implicit policy export.
func (EmailAddressConfiguration) MarshalJSON() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}

// MarshalText denies implicit policy text export.
func (EmailAddressConfiguration) MarshalText() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}

// Format redacts retained proof, key and policy custody.
func (EmailRemovalConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "reference.EmailRemovalConfiguration(redacted)")
}

// MarshalJSON denies implicit configuration export.
func (EmailRemovalConfiguration) MarshalJSON() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}

// MarshalText denies implicit configuration export.
func (EmailRemovalConfiguration) MarshalText() ([]byte, error) {
	return nil, email.ErrSensitiveSerialization
}
