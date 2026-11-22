package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type refreshStoredCredential kernel.CredentialAdmission

// The request key survives terminal execution. Persist the exact vault
// commitment, never a second copy of its recoverable provider credentials.
type providerRefreshInput struct {
	Binding      rpStoredBinding
	Account      identity.Account
	Credential   refreshStoredCredential
	SocialLink   uint64
	GrantVersion uint64
	GrantDigest  [32]byte
	Session      []identity.FeatureField
	CounterKeys  []uint32
	Network      string
	Started      time.Time
	ValidUntil   time.Time
}

func (providerRefreshInput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthpostgres.providerRefreshInput(redacted)"))
}

func providerRefreshRegistration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Operation: providerRefreshOperation(), Contributor: kernel.ContributorDescriptor{
		Owner: "identity/oauth/postgres", ContractID: "identity.oauth.provider-refresh", Version: 1,
	}}
}

func newProviderRefreshInput(binding identity.CommandBinding, account kernel.ProviderAccountAdmission, grant rpPreparedTokenSet, started, until time.Time) providerRefreshInput {
	return providerRefreshInput{Binding: rpStoredBinding(binding), Account: account.Account, Credential: refreshStoredCredential(account.Credential),
		SocialLink: account.SocialLinkVersion, GrantVersion: grant.Version, GrantDigest: providerRefreshGrantDigest(grant), Started: started, ValidUntil: until}
}

func (p providerRefreshInput) binding() identity.CommandBinding {
	return identity.CommandBinding(p.Binding)
}

func (p providerRefreshInput) account() kernel.ProviderAccountAdmission {
	return kernel.ProviderAccountAdmission{Account: p.Account, Credential: kernel.CredentialAdmission(p.Credential), SocialLinkVersion: p.SocialLink}
}

func (p providerRefreshInput) originalSession() (session.Session, error) {
	b := p.binding()
	return sessionpg.OriginalSessionFromFields(b.TenantID, b.UserID, p.Session)
}

func (p providerRefreshInput) commandFields() ([]identity.FeatureField, error) {
	frame, err := json.Marshal(p)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "oauth_refresh_input"}
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return append(append([]identity.FeatureField(nil), p.Session...),
		identity.FeatureField{Name: "provider-refresh.account-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.Account.Version}},
		identity.FeatureField{Name: "provider-refresh.social-link-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.SocialLink}},
		identity.FeatureField{Name: "provider-refresh.token-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.GrantVersion}},
		identity.FeatureField{Name: "provider-refresh.input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}), nil
}

func (s *LinkService) providerRefreshCommand(p providerRefreshInput, r ProviderRefreshRequest) (identity.Command, kernel.CommandCounterPlan, error) {
	fields, err := p.commandFields()
	if err != nil {
		return identity.Command{}, kernel.CommandCounterPlan{}, err
	}
	original, err := p.originalSession()
	if err != nil || !s.possesses(p.binding().TenantID, r.Session, r.CSRFToken, original) {
		return identity.Command{}, kernel.CommandCounterPlan{}, identity.ForbiddenError{}
	}
	spec, err := original.Bindings()
	if err != nil {
		return identity.Command{}, kernel.CommandCounterPlan{}, err
	}
	command, err := identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: p.binding(), Operation: providerRefreshOperation(), Fields: fields}, r.Session)
	if err != nil {
		return identity.Command{}, kernel.CommandCounterPlan{}, err
	}
	subject := risk.Subject{User: string(spec.UserID), Session: spec.SessionID, Network: p.Network}
	if len(p.CounterKeys) == 0 {
		return s.counters.PrepareCommandCounters(command, subject, p.Started)
	}
	return s.counters.PrepareCommandCountersWithRetainedKeys(command, subject, p.Started, p.CounterKeys)
}

func providerRefreshCounterKeys(command identity.Command) ([]uint32, error) {
	invalid := identity.InvalidInputError{Field: "oauth_refresh_counter_keys"}
	spec, ok := command.Feature()
	if !ok || spec.Operation != providerRefreshOperation() {
		return nil, invalid
	}
	for _, field := range spec.Fields {
		if field.Name != "counter.key-versions" {
			continue
		}
		wire := field.Value.Bytes
		if field.Value.Kind != identity.FeatureBytes || len(wire) == 0 || len(wire) > 16 || len(wire)%4 != 0 {
			return nil, invalid
		}
		keys := make([]uint32, 0, len(wire)/4)
		for len(wire) > 0 {
			key := binary.BigEndian.Uint32(wire[:4])
			if key == 0 || len(keys) != 0 && key >= keys[len(keys)-1] {
				return nil, invalid
			}
			keys = append(keys, key)
			wire = wire[4:]
		}
		return keys, nil
	}
	return nil, invalid
}

func (p providerRefreshInput) validAt(now time.Time) bool {
	return rpUTCTime(p.Started) && rpUTCTime(p.ValidUntil) && rpUTCTime(now) &&
		!now.Before(p.Started) && now.Before(p.ValidUntil) && p.ValidUntil.Sub(p.Started) <= 20*time.Second
}

func providerRefreshGrantDigest(grant rpPreparedTokenSet) [32]byte {
	if len(grant.Ciphertext) == 0 || len(grant.Ciphertext) > rpMaximumTokenCiphertext {
		return [32]byte{}
	}
	frame, err := json.Marshal(grant)
	if err != nil {
		return [32]byte{}
	}
	defer clear(frame)
	return sha256.Sum256(frame)
}

func (p providerRefreshInput) matchesGrant(grant rpPreparedTokenSet) bool {
	b := grant.Binding
	return p.GrantVersion != 0 && p.GrantVersion != math.MaxUint64 && p.GrantVersion == grant.Version &&
		p.SocialLink != 0 && p.SocialLink != math.MaxUint64 && p.SocialLink == b.SocialLinkVersion &&
		p.Account.Version == b.AccountVersion && p.Account.Provider == b.ProviderID && p.Account.Issuer == b.Issuer &&
		validProviderRefreshOutputScope(p.binding(), 1, b) && p.GrantDigest != ([32]byte{}) && p.GrantDigest == providerRefreshGrantDigest(grant)
}

func (s *LinkService) providerRefreshInputAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if s == nil || k.Namespace != s.requestKey.Namespace || k.Feature != providerRefreshRegistration() || k.Scope.RouteID != k.Feature.Operation.OperationID ||
		k.Scope.Method != "POST" || k.Scope.ActorKind != authorization.SubjectUser || k.PolicyVersion == 0 || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, identity.InvalidInputError{Field: "oauth_refresh_input"}
	}
	frame, err := json.Marshal(struct {
		Key     rpStoredKey
		Profile [32]byte
	}{rpStoredKey(k), s.profile})
	if err != nil {
		return envelope.Context{}, identity.InvalidInputError{Field: "oauth_refresh_input"}
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{
		"profile": "identity-oauth-provider-refresh-input-v1",
		"binding": base64.RawURLEncoding.EncodeToString(digest[:]),
	})
}

func (s *LinkService) openProviderRefreshInput(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) (providerRefreshInput, error) {
	var p providerRefreshInput
	aad, err := s.providerRefreshInputAAD(k)
	if err != nil {
		return p, err
	}
	plain, err := s.openRP(ctx, aad, wire, maximumProviderRefreshOutput)
	defer clear(plain)
	if err != nil {
		return p, err
	}
	if err := decodeRPOutput(plain, &p); err != nil {
		return providerRefreshInput{}, err
	}
	b := p.binding()
	if b.ValidateFor(k.Feature.Operation) != nil || b.CommandID != k.Admission.CommandID || b.TenantID != k.Scope.TenantID || b.ActorID != k.Scope.ActorID || b.ActorKind != k.Scope.ActorKind || b.PolicyVersion != k.PolicyVersion ||
		b.ActorID != identity.ActorID(b.UserID) || b.RecordID != string(p.Account.ID) || p.Account.Validate(b.TenantID, b.UserID) != nil || p.GrantDigest == ([32]byte{}) || !p.validAt(p.Started) {
		return providerRefreshInput{}, identity.ForbiddenError{}
	}
	return p, nil
}
