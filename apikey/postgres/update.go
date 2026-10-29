package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"slices"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

var _ apikey.Updater = (*Service)(nil)

func updateOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/apikey", OperationID: "identity.apikey.update", SchemaID: "apikey-update-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// Update renames or narrows an existing credential through the original keyed
// management coordinator. It never replaces digest custody or generates a key.
// Self and organization targets are explicit; matching retries retain the
// original committed snapshot, not a new read of mutable metadata.
func (s *Service) Update(ctx context.Context, r apikey.UpdateRequest) (apikey.UpdateResult, error) {
	if s == nil || s.config == nil || ctx == nil || r.Validate() != nil {
		return apikey.UpdateResult{}, apikey.ErrInvalid
	}
	r.Permissions = slices.Clone(r.Permissions)
	selected := *s
	selected.update = &r
	request := apikey.CreateRequest{Authentication: r.Authentication, IdempotencyKey: r.IdempotencyKey, Name: r.Name, Permissions: r.Permissions, CorrelationID: r.CorrelationID, Network: r.Network}
	mutation := apikey.Rotation{Authentication: r.Authentication, IdempotencyKey: r.IdempotencyKey, KeyID: r.KeyID, ExpectedVersion: r.ExpectedVersion, CorrelationID: r.CorrelationID, Network: r.Network}
	out, executionErr := selected.manage(ctx, request, &mutation, false, nil)
	if out.receipt.Validate() != nil {
		if executionErr == nil {
			executionErr = identity.UnavailableError{}
		}
		return apikey.UpdateResult{}, executionErr
	}
	result := apikey.UpdateResult{Receipt: out.receipt, Record: out.record, ConfigurationAuthority: out.configurationAuthority}
	configuration := s.config().Configuration
	if result.Record != nil {
		var err error
		configuration, err = s.selectedConfiguration(result.Record.ConfigurationID, result.Record.ConfigurationRevision)
		if err != nil {
			return apikey.UpdateResult{}, identity.UnavailableError{}
		}
	}
	if result.Validate(configuration) != nil {
		return apikey.UpdateResult{}, identity.UnavailableError{}
	}
	return result, executionErr
}

func (p *creationPhase) updating() bool { return p.service.update != nil }

func (p *creationPhase) advancesAuthority() bool {
	return p.mutation != nil && (!p.updating() || p.input.PreviousRecord != nil && !slices.Equal(p.input.PreviousRecord.Grant, p.input.Record.Grant))
}

func updatedRecord(prior apikey.Record, name string, grant []string) (apikey.Record, error) {
	if prior.Status != apikey.KeyActive || prior.Version == ^uint64(0) || grant == nil || len(grant) > len(prior.Grant) {
		return apikey.Record{}, apikey.ErrDenied
	}
	for _, permission := range grant {
		if !slices.Contains(prior.Grant, permission) {
			return apikey.Record{}, apikey.ErrDenied
		}
	}
	out := prior
	out.Version++
	out.Name, out.Grant = name, slices.Clone(grant)
	if !slices.Equal(prior.Grant, grant) {
		if prior.AuthorityVersion == ^uint64(0) {
			return apikey.Record{}, apikey.ErrDenied
		}
		out.AuthorityVersion++
		out.RootVersion++
	}
	return out, nil
}

func (s *Service) updateIntent(r apikey.UpdateRequest) (identity.RequestIntent, error) {
	wire, err := json.Marshal(struct {
		KeyID           apikey.KeyID
		ExpectedVersion uint64
		OrganizationID  apikey.OrganizationID
		Name            string
		Permissions     []string
		Configuration   apikey.ConfigurationSpec
		PolicyID        string
		PolicyVersion   uint64
		Network         string
	}{r.KeyID, r.ExpectedVersion, r.OrganizationID, r.Name, r.Permissions, s.config().Configuration.Spec(), s.config().PolicyID, s.config().PolicyVersion, r.Network})
	if err != nil {
		return identity.RequestIntent{}, apikey.ErrInvalid
	}
	digest := sha256.Sum256(wire)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "apikey.update.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}})
}

// Update uses the existing command-effect record for its original metadata
// and configuration epoch. Reading today's epoch would rewrite a successful
// name-only retry after another key is narrowed; no second journal is needed.
type updateSnapshot struct {
	Schema               uint16
	Record               []byte
	ConfigurationVersion uint64
}

func (p *creationPhase) effectRecord(record []byte) ([]byte, error) {
	if !p.updating() {
		return record, nil
	}
	version := p.input.ConfigurationAuthority.Version
	if p.advancesAuthority() {
		version++
	}
	return json.Marshal(updateSnapshot{Schema: 1, Record: record, ConfigurationVersion: version})
}

func decodeEffectRecord(wire []byte, c apikey.Configuration, operation string) (apikey.Record, *apikey.ConfigurationAuthorityBinding, error) {
	if operation != "identity.apikey.update" {
		r, err := decodeRecord(wire, c)
		return r, nil, err
	}
	var snapshot updateSnapshot
	if len(wire) > maximumCommandEffectBytes || decodeCanonical(wire, &snapshot) != nil || snapshot.Schema != 1 || snapshot.ConfigurationVersion == 0 {
		return apikey.Record{}, nil, identity.UnavailableError{}
	}
	r, err := decodeRecord(snapshot.Record, c)
	if err != nil || r.Status != apikey.KeyActive || r.Version < 2 {
		return apikey.Record{}, nil, identity.UnavailableError{}
	}
	authority := &apikey.ConfigurationAuthorityBinding{TenantID: r.Owner.Spec().TenantID, ConfigurationID: r.ConfigurationID, Version: snapshot.ConfigurationVersion}
	return r, authority, nil
}

func validUpdateProjection(x creationInput, prior apikey.Record) bool {
	if x.PreviousConfiguration != nil || x.PreviousConfigurationAuthority != nil || !x.Configuration.AllowsVerification() || !prior.ExpiresAt.IsZero() && !x.VerifiedAt.Before(prior.ExpiresAt) {
		return false
	}
	prior.Owner = x.Record.Owner
	want, err := updatedRecord(prior, x.Record.Name, x.Record.Grant)
	return err == nil && reflect.DeepEqual(want, x.Record) && (want.AuthorityVersion == prior.AuthorityVersion || x.ConfigurationAuthority.Version != ^uint64(0))
}
