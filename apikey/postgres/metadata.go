package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

var _ apikey.MetadataService = (*Service)(nil)

// Get authenticates the real current human and returns only a copied stored
// metadata record under the exact self or explicit organization owner. Expired
// and revoked keys remain readable; the record is not verification authority.
// It performs no key verification, debit, counter admission or mutation.
func (s *Service) Get(ctx context.Context, r apikey.GetRequest) (out apikey.GetResult, err error) {
	if s == nil || s.config == nil || ctx == nil || r.Validate() != nil {
		return out, apikey.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = apikey.GetResult{}, identity.UnavailableError{}
		}
	}()
	selected, user, err := s.metadataOwner(ctx, r.Authentication, r.OrganizationID)
	if err != nil {
		return out, err
	}
	ids := selected.metadataConfigurationIDs()
	query := `SELECT configuration_id,record FROM identity_api_keys.keys WHERE tenant_id=$1 AND user_id=$2 AND key_id=$3 AND configuration_id=ANY($4::text[]) LIMIT 2`
	ownerID := string(user)
	if r.OrganizationID != "" {
		query = `SELECT configuration_id,record FROM identity_api_keys.keys WHERE tenant_id=$1 AND organization_id=$2 AND key_id=$3 AND configuration_id=ANY($4::text[]) LIMIT 2`
		ownerID = string(r.OrganizationID)
	}
	rows, err := selected.pool.Raw().Query(ctx, query, string(r.Authentication.TenantID), ownerID, string(r.KeyID), ids)
	if err != nil {
		return out, nativeError(ctx, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return out, nativeError(ctx, rows.Err())
		}
		return out, apikey.ErrDenied
	}
	var id string
	var wire []byte
	if err := rows.Scan(&id, &wire); err != nil {
		return out, nativeError(ctx, err)
	}
	if rows.Next() || rows.Err() != nil {
		return out, identity.UnavailableError{}
	}
	rows.Close() // Release the pool connection before current-profile I/O.
	configuration, err := selected.metadataProfile(ctx, r.Authentication.TenantID, user, id, "identity.apikey.get", r.CorrelationID)
	if err != nil {
		return out, err
	}
	record, err := decodeRecord(wire, configuration)
	if err != nil || record.ID != r.KeyID || !metadataOwnerMatches(record, r.Authentication.TenantID, user, r.OrganizationID) {
		return out, identity.UnavailableError{}
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	return apikey.GetResult{Record: record}, nil
}

// List returns a bounded live-view keyset page in bytewise ascending key-ID
// order. Every call repeats actual current human/owner/profile authorization;
// its cursor is only a scoped position and grants no future authority.
func (s *Service) List(ctx context.Context, r apikey.ListRequest) (out apikey.ListResult, err error) {
	if s == nil || s.config == nil || ctx == nil || r.Validate() != nil {
		return out, apikey.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = apikey.ListResult{}, identity.UnavailableError{}
		}
	}()
	selected, user, err := s.metadataOwner(ctx, r.Authentication, r.OrganizationID)
	if err != nil {
		return out, err
	}
	ids := slices.Clone(r.ConfigurationIDs)
	if len(ids) == 0 {
		ids = selected.metadataConfigurationIDs()
	}
	configurations := make([]apikey.Configuration, 0, len(ids))
	for _, id := range ids {
		configuration, err := selected.metadataProfile(ctx, r.Authentication.TenantID, user, id, "identity.apikey.list", r.CorrelationID)
		if err != nil {
			return out, err
		}
		configurations = append(configurations, configuration)
	}
	scope := metadataCursorScope(r.Authentication.TenantID, user, r.OrganizationID, configurations)
	after, err := decodeMetadataCursor(r.Cursor, scope)
	if err != nil {
		return out, err
	}
	if err := selected.metadataIndexReady(ctx); err != nil {
		return out, err
	}
	query := `SELECT key_id,configuration_id,record FROM unnest($3::text[]) AS selected(id) CROSS JOIN LATERAL
 (SELECT key_id,configuration_id,record FROM identity_api_keys.keys WHERE tenant_id=$1 AND user_id=$2 AND configuration_id=selected.id AND key_id COLLATE "C">$4 ORDER BY key_id COLLATE "C" LIMIT $5) AS page
 ORDER BY key_id COLLATE "C" LIMIT $5`
	ownerID := string(user)
	if r.OrganizationID != "" {
		query = `SELECT key_id,configuration_id,record FROM unnest($3::text[]) AS selected(id) CROSS JOIN LATERAL
 (SELECT key_id,configuration_id,record FROM identity_api_keys.keys WHERE tenant_id=$1 AND organization_id=$2 AND configuration_id=selected.id AND key_id COLLATE "C">$4 ORDER BY key_id COLLATE "C" LIMIT $5) AS page
 ORDER BY key_id COLLATE "C" LIMIT $5`
		ownerID = string(r.OrganizationID)
	}
	rows, err := selected.pool.Raw().Query(ctx, query, string(r.Authentication.TenantID), ownerID, ids, string(after), int(r.Limit)+1)
	if err != nil {
		return out, nativeError(ctx, err)
	}
	defer rows.Close()
	records := make([]apikey.Record, 0, int(r.Limit))
	previous := after
	next := ""
	for rows.Next() {
		var keyID apikey.KeyID
		var configurationID string
		var wire []byte
		if err := rows.Scan(&keyID, &configurationID, &wire); err != nil {
			return out, nativeError(ctx, err)
		}
		index := slices.Index(ids, configurationID)
		if index < 0 || keyID <= previous {
			return out, identity.UnavailableError{}
		}
		record, err := decodeRecord(wire, configurations[index])
		if err != nil || record.ID != keyID || !metadataOwnerMatches(record, r.Authentication.TenantID, user, r.OrganizationID) {
			return out, identity.UnavailableError{}
		}
		if len(records) == int(r.Limit) {
			next = encodeMetadataCursor(previous, scope)
			break
		}
		records = append(records, record)
		previous = keyID
	}
	if rows.Err() != nil {
		return out, nativeError(ctx, rows.Err())
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	return apikey.ListResult{Records: records, NextCursor: next}, nil
}

func (s *Service) metadataIndexReady(ctx context.Context) error {
	name := "identity_api_keys.identity_api_keys_metadata_user_page"
	if s.organizationID != "" {
		name = "identity_api_keys.identity_api_keys_metadata_org_page"
	}
	var ready bool
	// The selected paging migration is required even if another access path is
	// available. The migration runner owns definitions/checksums; this check
	// excludes absent/incomplete builds, not optimizer-dependent scan choices.
	if err := s.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_index WHERE indexrelid=to_regclass($1) AND indrelid='identity_api_keys.keys'::regclass AND indisvalid AND indisready AND indislive)`, name).Scan(&ready); err != nil {
		return nativeError(ctx, err)
	}
	if !ready {
		return identity.UnavailableError{}
	}
	return nil
}

func (s *Service) metadataOwner(ctx context.Context, authentication apikey.Authentication, target apikey.OrganizationID) (*Service, identity.UserID, error) {
	observed, err := s.human(ctx, authentication)
	if err != nil {
		return nil, "", err
	}
	bindings, err := observed.Session.Bindings()
	if err != nil {
		return nil, "", apikey.ErrDenied
	}
	directory, err := s.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.config().Profile.GlobalAuthorityID, TenantID: authentication.TenantID})
	if err != nil {
		return nil, "", nativeError(ctx, err)
	}
	if !directory.Enabled {
		return nil, "", apikey.ErrDenied
	}
	status, err := s.directory.GetStatus(ctx, identity.UserStatusQuery{TenantID: authentication.TenantID, UserID: bindings.UserID})
	if err != nil {
		return nil, "", nativeError(ctx, err)
	}
	if status.User.Status != identity.StatusActive {
		return nil, "", apikey.ErrDenied
	}
	if target == "" {
		return s, bindings.UserID, nil
	}
	if s.organization == nil || s.organization.repository == nil {
		return nil, "", apikey.ErrDenied
	}
	query := organization.CredentialAuthorityQuery{TenantID: authentication.TenantID, OrganizationID: organization.ID(target), ActorID: bindings.UserID}
	organizationObservation, err := s.organization.repository.ObserveCredentialAuthority(ctx, query)
	if errors.Is(err, organization.ErrForbidden) {
		return nil, "", apikey.ErrDenied
	}
	if err != nil {
		return nil, "", nativeError(ctx, err)
	}
	if organizationObservation.Validate(query, s.config().Clock.Now()) != nil {
		return nil, "", apikey.ErrDenied
	}
	selected := *s
	selected.organizationID = target
	selected.organization = &organizationComposition{repository: s.organization.repository, observation: &organizationObservation}
	return &selected, bindings.UserID, nil
}

func metadataOwnerMatches(record apikey.Record, tenant identity.TenantID, user identity.UserID, target apikey.OrganizationID) bool {
	owner := record.Owner.Spec()
	if owner.TenantID != tenant {
		return false
	}
	if target != "" {
		return owner.Kind == apikey.OwnerOrganization && owner.OrganizationID == target
	}
	return owner.Kind == apikey.OwnerUser && owner.UserID == user
}

func (s *Service) metadataConfigurationIDs() []string {
	ids := []string{s.issuanceConfiguration.Spec().ID}
	if c := s.config().LegacyConfiguration; c.Validate() == nil {
		ids = append(ids, c.Spec().ID)
	}
	slices.Sort(ids)
	return ids
}

func (s *Service) metadataProfile(ctx context.Context, tenant identity.TenantID, user identity.UserID, id, action, correlation string) (apikey.Configuration, error) {
	c, err := s.selectedConfiguration(id, 0)
	if err != nil || !c.AllowsVerification() {
		return apikey.Configuration{}, apikey.ErrDenied
	}
	selected := s.withConfiguration(c)
	if _, err := selected.configurationAuthority(ctx, tenant); err != nil {
		return apikey.Configuration{}, err
	}
	decision := selected.decision(tenant, user, action, "api-key", id, correlation)
	if selected.organizationID != "" {
		decision = selected.organizationDecision(tenant, authorization.SubjectUser, string(user), action, correlation)
	}
	if err := selected.allow(ctx, decision); err != nil {
		return apikey.Configuration{}, err
	}
	return c, nil
}

// A public hash scopes this position to a canonical query, not a principal or
// capability. A caller can construct a different position but must still pass
// all actual current authority checks and the owner-constrained SQL each time.
func metadataCursorScope(tenant identity.TenantID, actor identity.UserID, target apikey.OrganizationID, configurations []apikey.Configuration) [32]byte {
	specs := make([]apikey.ConfigurationSpec, len(configurations))
	for i, configuration := range configurations {
		specs[i] = configuration.Spec()
	}
	wire, _ := json.Marshal(struct {
		Tenant         identity.TenantID
		Actor          identity.UserID
		Organization   apikey.OrganizationID
		Configurations []apikey.ConfigurationSpec
	}{tenant, actor, target, specs})
	return sha256.Sum256(wire)
}

func encodeMetadataCursor(after apikey.KeyID, scope [32]byte) string {
	wire := make([]byte, 33, 33+len(after))
	wire[0] = 1
	copy(wire[1:], scope[:])
	wire = append(wire, string(after)...)
	return base64.RawURLEncoding.EncodeToString(wire)
}

func decodeMetadataCursor(cursor string, scope [32]byte) (apikey.KeyID, error) {
	if cursor == "" {
		return "", nil
	}
	if len(cursor) > 512 {
		return "", apikey.ErrInvalid
	}
	wire, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
	if err != nil || len(wire) < 34 || len(wire) > 161 || wire[0] != 1 || !bytes.Equal(wire[1:33], scope[:]) || base64.RawURLEncoding.EncodeToString(wire) != cursor {
		return "", apikey.ErrInvalid
	}
	return apikey.ParseKeyID(string(wire[33:]))
}
