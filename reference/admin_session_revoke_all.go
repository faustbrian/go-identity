package reference

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// HTTPAdminSessionRevokeAllConfiguration opts into revoking one authorized
// user's sessions across all audiences without changing other credentials.
// Leave quota settings empty when another selected feature owns shared admission.
type HTTPAdminSessionRevokeAllConfiguration HTTPAdminSessionRevokeConfiguration

func (HTTPAdminSessionRevokeAllConfiguration) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("reference.HTTPAdminSessionRevokeAllConfiguration(redacted)"))
}

func (HTTPAdminSessionRevokeAllConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func (HTTPAdminSessionRevokeAllConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

const adminSessionRevokeAllHistory = "identity_admin_session_revoke_all"
const adminSessionRevokeAllConfigField = "reference_http_admin_session_revoke_all"

type adminSessionRevokeAllState struct {
	native *session.AdminRevokeAllService
	adminSessionRevokeTransport
}

func validateAdminSessionRevokeAllSelection(c StoreConfiguration) error {
	if c.HTTPAdminSessionRevokeAll == nil {
		return nil
	}
	return validateAdminSessionMutation(c, HTTPAdminSessionRevokeConfiguration(*c.HTTPAdminSessionRevokeAll), adminSessionRevokeAllConfigField)
}

func composeAdminSessionRevokeAll(c StoreConfiguration, d ReferenceDependencies, rate *httpRateState, candidates []*organizationhttp.AdminRateLimiter) (*adminSessionRevokeAllState, error) {
	if c.HTTPAdminSessionRevokeAll == nil {
		return nil, nil
	}
	options := HTTPAdminSessionRevokeConfiguration(*c.HTTPAdminSessionRevokeAll)
	sessions, executor, config, transport, err := composeAdminSessionMutation(c, d, rate, candidates, options, adminSessionRevokeAllConfigField)
	if err != nil {
		return nil, err
	}
	native, err := session.NewAdminRevokeAllService(sessions, executor, config)
	if err != nil {
		transport.close()
		return nil, err
	}
	return &adminSessionRevokeAllState{native: native, adminSessionRevokeTransport: transport}, nil
}

func (s *adminSessionRevokeAllState) close() {
	if s != nil {
		s.adminSessionRevokeTransport.close()
	}
}

func (s *adminSessionRevokeAllState) AdminSessionRevokeAllWithAdmission(ctx context.Context, input sessionhttp.AdminSessionRevokeAllInput, admit func(context.Context, identity.UserID) error) (sessionhttp.AdminSessionRevokeAllOutput, error) {
	var out sessionhttp.AdminSessionRevokeAllOutput
	token, err := session.ParseToken(input.Bearer.Token())
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	commandID, err := identity.NewCommandID()
	if err != nil {
		return out, identity.UnavailableError{}
	}
	result, err := s.native.AdminSessionRevokeAllWithAdmission(ctx, session.AdminSessionRevokeAllRequest{
		TenantID: input.TenantID, TargetSubjectID: input.TargetSubjectID, CommandID: commandID,
		CorrelationID: string(commandID), Credential: credential, CSRF: input.CSRF,
	}, admit)
	if err != nil {
		return out, err
	}
	return sessionhttp.AdminSessionRevokeAllOutput{RevokedCount: result.RevokedCount, SubjectVersion: result.SubjectVersion}, nil
}

func (s *Server) adminSessionRevokeAllOps(network identityhttp.NetworkConfig) ([]identityhttp.OperationDescriptor, error) {
	native := s.state.features.adminSessionRevokeAll
	if native == nil {
		return nil, nil
	}
	feature, err := sessionhttp.NewAdminSessionRevokeAllFeature(sessionhttp.AdminSessionRevokeAllConfig{
		Network: network, TrustedOrigins: []identityhttp.Origin{native.origin}, OriginalCookieName: native.cookie,
		Native: native, Rate: native.admin, MaximumDuration: native.maximum,
	})
	if err != nil {
		return nil, err
	}
	ops := feature.Operations()
	for i := range ops {
		ops[i].Handler = s.guardSessionLifetime(ops[i].Handler)
	}
	return ops, nil
}

func (s StoreSet) adminSessionRevokeAllMigrationCatalog(ctx context.Context, existing []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.adminSessionRevokeAll == nil {
		return existing, nil
	}
	schema := s.state.features.adminSessionRevokeAll.schema
	// Reference atomically records each migration receipt with its DDL. Select
	// the index's offline history from the first installation.
	history, err := (sessionpg.AdminRevokeAllMigrationSource{Schema: schema, Version: 1, IndexVersion: 2}).LoadOffline(ctx)
	if err != nil {
		return nil, err
	}
	return append(existing, migrationHistory{
		namespace: adminSessionRevokeAllHistory, history: history,
		owners: map[migrations.Version]ModuleID{1: "identity/session/postgres", 2: "identity/session/postgres"},
		guards: []migrationGuard{
			{version: 1, schema: schema, tables: []string{"admin_set_revocations"}},
			{version: 2, schema: schema, tables: []string{"session_admin_active_subject_order"}},
		},
	}), nil
}
