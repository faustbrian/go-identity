package passwordpostgres

import (
	"fmt"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// PhonePasswordResetRiskConfig pins existing native risk and counter owners.
// Deployment configuration is fixed; the native executor's user scope is not.
// The phone owner resolves that scope from the authenticated original browser
// and verified number, never a startup-wide account or request-body user ID.
type PhonePasswordResetRiskConfig struct {
	Store                  riskpg.Config
	Issuer                 risk.PhoneEvidenceIssuerConfig
	Coordinator            kernel.CoordinatorConfig
	PolicyID               string
	RetentionPolicyVersion uint64
}

type phonePasswordRecoveryRiskConfig = PhonePasswordResetRiskConfig

// Format prevents risk wrapping keys from entering diagnostics.
func (PhonePasswordResetRiskConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.PhonePasswordResetRiskConfig(redacted)"))
}

// MarshalJSON rejects implicit risk composition export.
func (PhonePasswordResetRiskConfig) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// MarshalText rejects implicit risk composition export.
func (PhonePasswordResetRiskConfig) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

type phonePasswordRecoveryRisk struct {
	issuer     risk.PhoneEvidenceIssuer
	repository *riskpg.Repository
}

// Build an invocation-local real issuer and protected-use participant over the
// SAME durable owner and counter store. Only executor authorization scope varies.
// No provider, clock, database, journal or credential callback runs here. The
// request-key preparation retains the complete original PhoneEvidenceRequest;
// PrepareUse resolves its existing encrypted issuance, never today's new facts.
func newPhonePasswordRecoveryRisk(pool *database.Pool, c phonePasswordRecoveryRiskConfig, caller authorization.DecisionContext, resolved identity.UserID) (*phonePasswordRecoveryRisk, error) {
	if pool == nil || pool.Raw() == nil || caller.Validate() != nil || caller.Request.Subject.Kind != authorization.SubjectServiceAccount || caller.Request.Resource.Type != "identity.user" || caller.Request.Resource.ID != "" || (caller.Request.Action != "identity.phone.password-reset-request" && caller.Request.Action != "identity.phone.password-reset-complete") || c.Issuer.Executor != nil || c.Store.UseIssuer != nil || c.Store.UseCounters == nil {
		return nil, risk.ErrInvalidPolicy
	}
	if _, err := identity.ParseIdentifierID(string(resolved)); err != nil {
		return nil, risk.ErrInvalidPolicy
	}
	if _, err := identity.ParseIdentifierID(string(caller.Request.Tenant)); err != nil {
		return nil, risk.ErrInvalidPolicy
	}
	// Issuance has no protected-use authority. The native counter configuration
	// requires the original issuer and belongs only to the consuming participant
	// built below; the evaluator already owns issuance's same durable counters.
	issuance := c.Store
	issuance.UseCounters = nil
	issuing, err := riskpg.NewRepository(issuance)
	if err != nil {
		return nil, err
	}
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, risk.ErrInvalidPolicy
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, risk.ErrInvalidPolicy
	}
	trusted := caller.Clone()
	trusted.Request.Action = "identity.risk.evaluate"
	trusted.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(resolved)}
	executor, err := riskpg.NewExecutor(riskpg.ExecutorConfig{Pool: pool, Repository: issuing, Audit: audits, Lifecycle: outbox, Coordinator: c.Coordinator, Caller: trusted, PolicyID: c.PolicyID, RetentionPolicyVersion: c.RetentionPolicyVersion})
	if err != nil {
		return nil, err
	}
	configuration := c.Issuer
	configuration.Executor = executor
	issuer, err := risk.NewPhoneEvidenceIssuer(configuration)
	if err != nil {
		return nil, err
	}
	// NewRepository checks complete retained issuer-key/policy identity; it
	// borrows the original durable counter state rather than a new quota lane.
	consuming := c.Store
	consuming.UseIssuer = &issuer
	repository, err := riskpg.NewRepository(consuming)
	if err != nil {
		return nil, err
	}
	return &phonePasswordRecoveryRisk{issuer: issuer, repository: repository}, nil
}
