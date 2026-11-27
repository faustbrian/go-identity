package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
)

func readProxyProviderEpoch(ctx context.Context, a *ProviderAuthority, k ProviderAuthorityKey, profileVersion uint64) (uint64, error) {
	if a == nil {
		return 0, nil // The explicit legacy profile has no live epoch.
	}
	current, err := a.Current(ctx, k)
	if err != nil {
		return 0, err
	}
	if !current.Enabled || current.Version == 0 || current.ProfileVersion != profileVersion {
		return 0, identity.ForbiddenError{}
	}
	return current.Version, nil
}

func requireProxyProviderAuthority(ctx context.Context, a *ProviderAuthority, b oauth.ProxyOIDCEvidenceBinding) error {
	if (a == nil) != (b.ProviderAuthorityEpoch == 0) {
		return identity.ForbiddenError{}
	}
	epoch, err := readProxyProviderEpoch(ctx, a, ProviderAuthorityKey{TenantID: b.TenantID, ProviderID: b.ProviderID}, b.ProviderVersion)
	if err != nil {
		return err
	}
	if epoch != b.ProviderAuthorityEpoch {
		return identity.ForbiddenError{}
	}
	return nil
}
