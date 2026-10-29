package reference

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-postgres"
)

// APIKeyConfiguration selects native password-bearer key management,
// independently of HTTP. User ownership is the default; organization ownership
// requires the explicit selected native owner. Modern issuance remains mandatory; legacy digest
// import and verification require explicit selection. Current session/profile,
// policy, coordinator,
// request-key and risk-evaluator ownership are derived from this graph; callers
// supply no replacement authority or domain store. Counters must select the
// same protected policy/version and schema, with lockout enforcement. Pepper,
// envelope and risk key history must be retained for original pending commands.
// Construction copies custody; MaximumDuration is positive and at most5s.
type APIKeyConfiguration struct {
	// MetadataPaging selects the native additive owner paging indexes. Exact-key
	// Get needs no extra schema; selected HTTP List requires this explicit choice.
	MetadataPaging bool
	// OrganizationOwned selects the actual organization repository and its
	// independent credential epoch. Organization must also be configured.
	OrganizationOwned    bool
	Configuration        apikey.Configuration
	MaximumDuration      time.Duration
	PolicyID             string
	Pepper               apikey.Pepper
	Counters             riskpg.Config
	RiskConfigurationID  string
	RiskKeys             []risk.EvidenceKey
	ActiveEnvelopeKeyID  string
	RetainedEnvelopeKeys map[string][]byte
	// LegacyConfiguration independently selects one verify-only SHA-256 profile.
	// Zero preserves modern-only storage, startup and operation selection.
	LegacyConfiguration apikey.Configuration
	// ValidateCanonicalKeyID is required only with LegacyConfiguration. It must
	// honor cancellation, preserve existing canonical IDs and be concurrency-safe.
	// It supplies identifier policy, never owner or import-source authority.
	ValidateCanonicalKeyID func(context.Context, apikey.KeyID) error
}

type apiKeyState struct {
	native         *apikeypg.Service
	selfOnly       *apikeypg.Service
	maximum        time.Duration
	legacy         bool
	organization   bool
	metadataPaging bool
}

func composeAPIKey(c StoreConfiguration, pool *postgres.Pool, sessions *sessionState, organizations *organizationState, policy risk.Policy, evaluation risk.Evaluator) (*apiKeyState, error) {
	if c.APIKey == nil {
		return nil, nil
	}
	n := *c.APIKey
	invalid := identity.InvalidInputError{Field: "reference_api_key"}
	if n.OrganizationOwned && (organizations == nil || organizations.repository == nil) {
		return nil, identity.InvalidInputError{Field: "reference_api_key_organization"}
	}
	if c.OTP == nil || c.Session == nil || c.PasswordSignin == nil || sessions == nil || c.PasswordSignin.MFA != nil || n.Counters.Schema != c.Velocity.Schema || n.Counters.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion || n.Counters.CommandCounters == nil || !n.Counters.EnforceLockouts {
		return nil, invalid
	}
	selection, err := sessionAdmissionSelection(c)
	if err != nil || selection.Verified == nil {
		return nil, invalid
	}
	probe, _ := session.ParseToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	lookup := make(map[uint32]session.DigestKey, len(c.Session.Native.Validation.LookupKeys))
	for _, key := range c.Session.Native.Validation.LookupKeys {
		digest, err := probe.Digest(key, "validation")
		if err != nil {
			return nil, invalid
		}
		if _, exists := lookup[digest.KeyVersion]; exists {
			return nil, invalid
		}
		lookup[digest.KeyVersion] = key
	}
	counters, err := riskpg.NewRepository(n.Counters)
	if err != nil {
		return nil, invalid
	}
	query := c.OTP.RequestKeys.Policy
	query.Clock = clock.System{}
	coordinator := c.OTP.Coordinator
	coordinator.QueryPolicy, coordinator.AdmissionPolicy = &query, &query
	nativeConfig := apikeypg.ServiceConfig{Configuration: n.Configuration, LegacyConfiguration: n.LegacyConfiguration, ValidateCanonicalKeyID: n.ValidateCanonicalKeyID, Clock: clock.System{}, MaximumDuration: n.MaximumDuration, Sessions: sessions.reader, Session: c.Session.Native.Execution.Repository, Profile: *selection.Verified, LookupKeys: lookup, Authorization: query.Authorization, PolicyID: n.PolicyID, PolicyVersion: query.PolicyVersion, Pepper: n.Pepper, Counters: counters, Risk: risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: n.RiskConfigurationID, Keys: n.RiskKeys}, CounterPolicy: policy, Coordinator: coordinator, RequestKeys: c.OTP.RequestKeys, ActiveEnvelopeKeyID: n.ActiveEnvelopeKeyID, RetainedEnvelopeKeys: n.RetainedEnvelopeKeys}
	selfOnly, err := apikeypg.NewService(pool, nativeConfig)
	if err != nil {
		return nil, invalid
	}
	native := selfOnly
	if n.OrganizationOwned {
		native, err = apikeypg.NewOrganizationService(pool, nativeConfig, organizations.repository)
		if err != nil {
			return nil, invalid
		}
	}
	// Both immutable views borrow the same native owners/pool. HTTP selection
	// must narrow authority before mutation, not merely suppress its response.
	return &apiKeyState{native: native, selfOnly: selfOnly, maximum: n.MaximumDuration, legacy: n.LegacyConfiguration != (apikey.Configuration{}), organization: n.OrganizationOwned, metadataPaging: n.MetadataPaging}, nil
}

func (APIKeyConfiguration) Format(s fmt.State, _ rune) {
	io.WriteString(s, "reference.APIKeyConfiguration(redacted)")
}
func (APIKeyConfiguration) MarshalJSON() ([]byte, error) { return nil, apikey.ErrDisclosure }
func (APIKeyConfiguration) MarshalText() ([]byte, error) { return nil, apikey.ErrDisclosure }
