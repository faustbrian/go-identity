package postgres

import (
	"context"
	"crypto/subtle"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
)

type proxyPreviewCallbackInput struct {
	row       proxyPreviewRow
	binding   proxyPreviewBinding
	admission *oauthproxy.PreviewCompletionAdmission
	request   oauthproxy.PreviewCompletionRequest
	authority *ProviderAuthority
}

// Only the acknowledged native preparation path calls this after its counted
// risk admission. The preview supplies evidence, never a provider exchange or
// a second account/session completion path.
func (p *signinCallbackPhase) openProxyPreview(ctx context.Context) (oauth.ProviderIdentity, time.Time, error) {
	if p.preview == nil || p.preview.admission == nil || p.authenticatedAt.IsZero() {
		return oauth.ProviderIdentity{}, time.Time{}, identity.ForbiddenError{}
	}
	preview := p.preview
	if err := requireProxyProviderAuthority(ctx, preview.authority, preview.binding.Evidence); err != nil {
		return oauth.ProviderIdentity{}, time.Time{}, err
	}
	evidence, err := preview.admission.Open(ctx, preview.binding.Evidence, p.flow.original, preview.request)
	if err != nil {
		return oauth.ProviderIdentity{}, time.Time{}, err
	}
	verified, ok := evidence.Identity()
	if !ok {
		return oauth.ProviderIdentity{}, time.Time{}, identity.ForbiddenError{}
	}
	feature, ok := p.original.Feature()
	if !ok {
		return oauth.ProviderIdentity{}, time.Time{}, identity.ForbiddenError{}
	}
	digest := evidence.EnvelopeDigest()
	for _, field := range feature.Fields {
		if field.Name != "oauth.proxy.envelope" {
			continue
		}
		if field.Value.Kind != identity.FeatureBytes || subtle.ConstantTimeCompare(field.Value.Bytes, digest[:]) != 1 {
			return oauth.ProviderIdentity{}, time.Time{}, identity.ForbiddenError{}
		}
		return verified, evidence.ExpiresAt(), nil
	}
	return oauth.ProviderIdentity{}, time.Time{}, identity.ForbiddenError{}
}
