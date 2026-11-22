package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// A vault envelope is at most 64 KiB. The outer JSON includes its base64
// encoding, both bounded scope lists and the authenticated metadata.
const maximumProviderRefreshOutput = 128 << 10

type providerRefreshOutput struct {
	Schema    uint8
	Rejected  bool
	Successor *rpPreparedTokenSet
}

func providerRefreshOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.account.refresh-token",
		SchemaID: "identity.account.refresh-token.pg-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func (s *LinkService) providerRefreshOutputAAD(binding identity.CommandBinding, original rpPreparedTokenSet, generation uint64) (envelope.Context, error) {
	b := original.Binding
	if !validProviderRefreshOutputScope(binding, generation, b) {
		return envelope.Context{}, identity.InvalidInputError{Field: "oauth_refresh_output"}
	}
	return s.providerRefreshOutputCommitmentAAD(binding, providerRefreshGrantDigest(original), generation)
}

// The digest commits the exact predecessor envelope and metadata. Restoration
// can authenticate journal output without a database read or retained grant.
func (s *LinkService) providerRefreshOutputCommitmentAAD(binding identity.CommandBinding, digest [32]byte, generation uint64) (envelope.Context, error) {
	if s == nil || generation == 0 || digest == ([32]byte{}) || binding.ValidateFor(providerRefreshOperation()) != nil {
		return envelope.Context{}, identity.InvalidInputError{Field: "oauth_refresh_output"}
	}
	frame, err := json.Marshal(struct {
		Binding    rpStoredBinding
		Original   [32]byte
		Generation uint64
		Profile    [32]byte
	}{rpStoredBinding(binding), digest, generation, s.profile})
	if err != nil {
		return envelope.Context{}, identity.InvalidInputError{Field: "oauth_refresh_output"}
	}
	defer clear(frame)
	bound := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{
		"profile": "identity-oauth-provider-refresh-output-v1",
		"binding": base64.RawURLEncoding.EncodeToString(bound[:]),
	})
}

func validProviderRefreshOutputScope(binding identity.CommandBinding, generation uint64, account rpTokenVaultBinding) bool {
	return generation != 0 && binding.ValidateFor(providerRefreshOperation()) == nil && binding.ActorKind == authorization.SubjectUser &&
		binding.ActorID == identity.ActorID(binding.UserID) && binding.TenantID == account.TenantID && binding.UserID == account.UserID &&
		binding.RecordID == string(account.AccountID)
}

// Called by the refresh preparation owner only after the coordinator has
// acknowledged the original start marker. It does not reserve or retry the
// provider request. An unusable grant retains evidence, not a claim that the
// provider revoked every access token or a reason why it rejected the grant.
func (s *LinkService) generateProviderRefreshOutput(ctx context.Context, binding identity.CommandBinding, original rpPreparedTokenSet, provider *oauth.OAuth2RefreshProvider, generation uint64) ([]byte, error) {
	if ctx == nil || provider == nil {
		return nil, identity.InvalidInputError{Field: "oauth_refresh_output"}
	}
	aad, err := s.providerRefreshOutputAAD(binding, original, generation)
	if err != nil {
		return nil, err
	}
	grant, err := s.openStoredProviderRefresh(ctx, original)
	if err != nil {
		return nil, err
	}
	defer grant.Destroy()
	result, err := provider.Refresh(ctx, grant)
	output := providerRefreshOutput{Schema: 1}
	if err != nil {
		var providerError *oauth.Error
		if !errors.As(err, &providerError) || providerError.Kind() != oauth.RefreshGrantRejected {
			return nil, err
		}
		output.Rejected = true
	} else {
		next, err := s.sealStoredProviderRefresh(ctx, original, result)
		if err != nil {
			return nil, err
		}
		output.Successor = &next
	}
	plain, err := json.Marshal(output)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	defer clear(plain)
	wire, err := s.sealRP(ctx, aad, plain)
	if err != nil || len(wire) == 0 || len(wire) > maximumProviderRefreshOutput {
		return nil, identity.UnavailableError{}
	}
	return wire, nil
}

func (s *LinkService) openProviderRefreshOutput(ctx context.Context, binding identity.CommandBinding, original rpPreparedTokenSet, generation uint64, wire []byte) (providerRefreshOutput, error) {
	if !validProviderRefreshOutputScope(binding, generation, original.Binding) {
		return providerRefreshOutput{}, identity.ForbiddenError{}
	}
	output, err := s.decodeProviderRefreshOutput(ctx, binding, providerRefreshGrantDigest(original), generation, wire)
	if err != nil {
		return providerRefreshOutput{}, err
	}
	if output.Successor != nil {
		if !providerRefreshVaultTransition(original, *output.Successor) {
			clear(output.Successor.Ciphertext)
			return providerRefreshOutput{}, identity.ForbiddenError{}
		}
		grant, err := s.openStoredProviderRefresh(ctx, *output.Successor)
		grant.Destroy()
		if err != nil {
			clear(output.Successor.Ciphertext)
			return providerRefreshOutput{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		if output.Successor != nil {
			clear(output.Successor.Ciphertext)
		}
		return providerRefreshOutput{}, err
	}
	return output, nil
}

func (s *LinkService) decodeProviderRefreshOutput(ctx context.Context, binding identity.CommandBinding, digest [32]byte, generation uint64, wire []byte) (providerRefreshOutput, error) {
	if ctx == nil {
		return providerRefreshOutput{}, identity.InvalidInputError{Field: "oauth_refresh_output"}
	}
	if err := ctx.Err(); err != nil {
		return providerRefreshOutput{}, err
	}
	aad, err := s.providerRefreshOutputCommitmentAAD(binding, digest, generation)
	if err != nil {
		return providerRefreshOutput{}, err
	}
	plain, err := s.openRP(ctx, aad, wire, maximumProviderRefreshOutput)
	defer clear(plain)
	if err != nil {
		return providerRefreshOutput{}, err
	}
	var output providerRefreshOutput
	if err := decodeRPOutput(plain, &output); err != nil || output.Schema != 1 || output.Rejected != (output.Successor == nil) {
		if output.Successor != nil {
			clear(output.Successor.Ciphertext)
		}
		return providerRefreshOutput{}, identity.ForbiddenError{}
	}
	return output, nil
}
