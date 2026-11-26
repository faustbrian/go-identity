package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/oauth/onetap"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Encrypted preparation retains only tokenless fields. It cannot reconstruct
// Google credentials, session bearer, CSRF, or a refreshed authority deadline.
type oneTapCallbackOutput struct {
	Schema                         uint8
	Fields                         []identity.FeatureField
	ProviderExpiresAt, ReadStarted time.Time
	Admission                      signinStoredAdmission
}

func (p *oneTapCallbackPhase) outputAAD(generation uint64) (envelope.Context, error) {
	if p == nil || p.service == nil || generation == 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	f, ok := p.original.Feature()
	if !ok {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	return oneTapEnvelopeContext("identity-oauth-onetap-callback-output-v1", struct {
		Original    rpStoredBinding
		Callback    identity.FeatureCommandSpec
		GrantDigest [32]byte
		Generation  uint64
	}{rpStoredBinding(p.grant.Original), f, p.grant.CiphertextDigest, generation})
}

func (p *oneTapCallbackPhase) generate(ctx context.Context, generation uint64, admission risk.AuthenticationAdmission) ([]byte, error) {
	if p.authenticatedAt.IsZero() || p.generated != 0 || p.issuer == nil {
		return nil, identity.ForbiddenError{}
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	start, b := p.service.start, p.binding
	c := start.config()
	verified, err := p.service.validator.Validate(ctx, onetap.ProviderBoundAdapterBinding{
		Transaction: p.browser, Expected: p.browserSpec.Transaction.Binding, Cookie: p.cookie,
	}, p.request.Callback)
	if err != nil {
		var failure *onetap.Error
		if errors.As(err, &failure) && failure.Kind() == onetap.Unavailable {
			return nil, identity.UnavailableError{}
		}
		return nil, identity.ForbiddenError{}
	}
	retained, err := verified.Original()
	i := verified.Identity()
	if err != nil || retained != p.browserSpec || i.ProviderID() != start.selected.ProviderID || i.Issuer() != c.Provider.Profile().Issuer || i.Subject() == "" {
		return nil, identity.ForbiddenError{}
	}
	account, err := start.directory.GetProviderSigninAccount(ctx, kernel.ProviderSigninAccountQuery{TenantID: b.TenantID, Provider: i.ProviderID(), Issuer: i.Issuer(), Subject: i.Subject()})
	if err != nil {
		return nil, err
	}
	// The factor reader caps its own primary read at five seconds. A longer
	// valid callback budget must not bypass or disable that authority check.
	factors, err := mfapg.ReadOAuthSigninFactors(ctx, start.pool, b.TenantID, account.Account.UserID, min(c.MaximumDuration, 5*time.Second))
	if err != nil {
		return nil, err
	}
	policy, err := p.service.policy.Get(ctx, authoritypg.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), SubjectID: authorization.SubjectID(account.Account.UserID), PolicyNamespace: p.service.config.PolicyNamespace})
	if err != nil {
		return nil, err
	}
	now := c.Issuance.Clock.Now().UTC()
	if err := p.checkBrowser(now, p.readStarted); err != nil {
		return nil, err
	}
	if err := admission.CheckAt(ctx, now); err != nil {
		return nil, err
	}
	until := p.validUntil(i.EvidenceExpiresAt(), p.readStarted)
	if !until.After(now) {
		return nil, identity.ForbiddenError{}
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		return nil, err
	}
	family, err := identity.NewSubjectID()
	if err != nil {
		return nil, err
	}
	vector, err := oauthSigninAuthority(p.directory, p.service.config.PolicyNamespace, account, factors.Version(), policy.Version, string(id), string(family))
	if err != nil {
		return nil, err
	}
	proof := auth.Proof{ID: auth.ProofID(b.CommandID), Tenant: string(b.TenantID), Subject: string(account.Account.UserID), Method: "oauth", Assurance: auth.AssuranceSingleFactor,
		Purpose: "session-issue", Audience: p.service.config.Audience, IssuedAt: now, ExpiresAt: until}
	prepared, err := p.issuer.PrepareOneTap(b, session.SessionSpec{SessionID: string(id), FamilyID: string(family), TenantID: b.TenantID,
		UserID: account.Account.UserID, Audience: p.service.config.Audience, Version: 1, FamilyVersion: 1,
		Remember: p.browserSpec.Transaction.Binding.Intent.Remember, Authority: vector, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified,
			Proof: proof, ProofVersion: start.selected.ProviderVersion, CredentialID: string(account.Credential.Credential.ID), CredentialVersion: account.Credential.Credential.Version},
		IssuedAt: now, LastActivityAt: now})
	if err != nil {
		return nil, err
	}
	record, ok := prepared.Session()
	if !ok {
		return nil, identity.UnavailableError{}
	}
	fields, err := oneTapCallbackFields(record, account)
	if err != nil {
		return nil, err
	}
	wire, err := start.sealOneTap(ctx, aad, oneTapCallbackOutput{Schema: 1, Fields: fields, ProviderExpiresAt: i.EvidenceExpiresAt(),
		ReadStarted: p.readStarted, Admission: signinStoredAdmission(admission.Prepared())}, 128<<10)
	if err != nil {
		return nil, err
	}
	p.prepared, p.generated = prepared, generation
	return wire, nil
}

func (p *oneTapCallbackPhase) validUntil(provider, observed time.Time) time.Time {
	until := provider
	for _, limit := range [...]time.Time{observed.Add(20 * time.Second), p.browserSpec.Transaction.Binding.ExpiresAt, p.grant.Grant.ExpiresAt} {
		if limit.Before(until) {
			until = limit
		}
	}
	return until
}

func oneTapCallbackFields(record session.Session, account kernel.ProviderAccountAdmission) ([]identity.FeatureField, error) {
	fields, err := sessionpg.OneTapCallbackSessionFields(record)
	if err != nil {
		return nil, err
	}
	accountFields, err := kernel.OAuthSigninAccountFields(account)
	if err != nil {
		return nil, err
	}
	return append(fields, accountFields...), nil
}

func (p *oneTapCallbackPhase) restore(ctx context.Context, generation uint64, wire []byte) (*oneTapCallbackExecution, identity.Command, error) {
	deny := func() (*oneTapCallbackExecution, identity.Command, error) {
		return nil, identity.Command{}, identity.ForbiddenError{}
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, identity.Command{}, err
	}
	var stored oneTapCallbackOutput
	if err := p.service.start.openOneTap(ctx, aad, wire, 192<<10, &stored); err != nil {
		return nil, identity.Command{}, err
	}
	if stored.Schema != 1 || !rpUTCTime(stored.ReadStarted) || !rpUTCTime(stored.ProviderExpiresAt) || stored.ReadStarted.Before(p.grant.IssuedAt) {
		return deny()
	}
	f, _ := p.original.Feature()
	f.Fields = append(f.Fields, stored.Fields...)
	command, err := identity.NewFeaturePreAuthCommand(f, p.request.FlowCookie)
	if err != nil {
		return deny()
	}
	record, err := sessionpg.OneTapCallbackSession(command)
	if err != nil {
		return deny()
	}
	account, err := kernel.OneTapCallbackAccount(command)
	if err != nil {
		return deny()
	}
	fields, err := oneTapCallbackFields(record, account)
	if err != nil || !sameRPFields(fields, stored.Fields) {
		return deny()
	}
	spec, err := record.Bindings()
	if err != nil {
		return deny()
	}
	proof := spec.Authentication.Proof
	if spec.IssuedAt.Before(stored.ReadStarted) || !proof.ExpiresAt.Equal(p.validUntil(stored.ProviderExpiresAt, stored.ReadStarted)) ||
		spec.TenantID != p.binding.TenantID || spec.UserID != account.Account.UserID || spec.Audience != p.service.config.Audience ||
		account.Account.Provider != p.service.start.selected.ProviderID || account.Account.Issuer != p.service.start.config().Provider.Profile().Issuer ||
		spec.Authentication.ProofVersion != p.service.start.selected.ProviderVersion || spec.Authentication.CredentialID != string(account.Credential.Credential.ID) ||
		spec.Authentication.CredentialVersion != account.Credential.Credential.Version {
		return deny()
	}
	vector, err := spec.Authority.Bindings()
	if err != nil {
		return deny()
	}
	expected, err := oauthSigninAuthority(p.directory, p.service.config.PolicyNamespace, account, vector.Factor.Binding.Version, vector.Authorization.Version, spec.SessionID, spec.FamilyID)
	if err != nil {
		return deny()
	}
	v, err := expected.Bindings()
	if err != nil || v != vector {
		return deny()
	}
	scope, subject := p.riskInputs()
	admission, err := p.service.start.custody.Restore(ctx, risk.PreparedAuthenticationAdmission(stored.Admission), scope, subject)
	if err != nil {
		return nil, identity.Command{}, err
	}
	if p.generated != 0 {
		original, ok := p.prepared.Session()
		if !ok || p.generated != generation {
			return deny()
		}
		originalFields, err := oneTapCallbackFields(original, account)
		if err != nil || !sameRPFields(originalFields, fields) {
			return deny()
		}
	}
	return &oneTapCallbackExecution{record: record, admission: admission, readStarted: stored.ReadStarted, generation: generation, digest: sha256.Sum256(wire)}, command, nil
}
