package postgres

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// This decodes historical metadata only after an exact terminal coordinator
// receipt. The RP row owns the encrypted response projection, not another
// outcome journal. No state proof, PKCE, session bearer, risk or expiry is
// restored into new execution or delivery permission.
func (p *signinCallbackPhase) committedProjection(ctx context.Context) (*signinExecution, error) {
	if !p.flow.erased || len(p.flow.resultFields) == 0 {
		return nil, identity.ForbiddenError{}
	}
	started := time.Now()
	f, _ := p.original.Feature()
	f.Fields = append(f.Fields, p.flow.resultFields...)
	command, err := identity.NewFeaturePreAuthCommand(f, p.request.FlowCookie)
	if err != nil {
		return nil, err
	}
	record, err := sessionpg.OAuthSigninSession(command)
	if err != nil {
		return nil, err
	}
	account, err := kernel.OAuthSigninAccount(command)
	if err != nil {
		return nil, err
	}
	fields, err := sessionpg.OAuthSigninSessionFields(record)
	if err != nil {
		return nil, err
	}
	a, err := kernel.OAuthSigninAccountFields(account)
	if err != nil {
		return nil, err
	}
	if !sameRPFields(append(fields, a...), p.flow.resultFields) {
		return nil, identity.ForbiddenError{}
	}
	spec, err := record.Bindings()
	if err != nil {
		return nil, err
	}
	flow, err := p.flow.original.Bindings()
	if err != nil {
		return nil, err
	}
	originalRemember, _ := flow.Binding.Intent.Remember.Bindings()
	remember, _ := spec.Remember.Bindings()
	v := p.flow.binding
	if account.Account.Provider != v.Provider.ID || account.Account.Issuer != v.Provider.Issuer || account.Account.UserID != spec.UserID || spec.Audience != p.service.config.Audience || spec.Authentication.ProofVersion != v.Provider.Version || spec.Authentication.CredentialID != string(account.Credential.Credential.ID) || spec.Authentication.CredentialVersion != account.Credential.Credential.Version || remember != originalRemember {
		return nil, identity.ForbiddenError{}
	}
	vector, err := spec.Authority.Bindings()
	if err != nil {
		return nil, err
	}
	expected, err := p.authority(account, vector.Factor.Binding.Version, vector.Authorization.Version, spec.SessionID, spec.FamilyID)
	if err != nil {
		return nil, err
	}
	bindings, err := expected.Bindings()
	if err != nil || bindings != vector {
		return nil, identity.ForbiddenError{}
	}
	s := p.service.start
	if err := s.directory.CheckLinkedProviderCredential(ctx, account.Credential); err != nil {
		return nil, err
	}
	if err := mfapg.ReadOAuthSessionFactors(ctx, s.pool, record, s.config.MaximumDuration); err != nil {
		return nil, err
	}
	directory, err := s.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.config.GlobalAuthorityID, TenantID: spec.TenantID})
	if err != nil {
		return nil, err
	}
	if !directory.Enabled || directory.GlobalVersion != vector.Global.Version || directory.TenantVersion != vector.Tenant.Version {
		return nil, identity.ForbiddenError{}
	}
	policy, err := p.service.policy.Get(ctx, authoritypg.AuthorityScope{TenantID: authorization.TenantID(spec.TenantID), SubjectID: authorization.SubjectID(spec.UserID), PolicyNamespace: p.service.config.PolicyNamespace})
	if err != nil {
		return nil, err
	}
	if policy.Version != vector.Authorization.Version || time.Since(started) >= 20*time.Second {
		return nil, identity.ForbiddenError{}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &signinExecution{record: record, account: account}, nil
}
