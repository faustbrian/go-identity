package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"slices"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	email "github.com/faustbrian/go-identity/email"
	password "github.com/faustbrian/go-identity/password"
)

// Frozen native startup composition. The confirmation endpoint is independent
// of the post-confirmation callback bound inside the email grant. No request
// selects the endpoint, template, provider, locale chain or recipient key.
type signupDeliveryPreparation struct {
	owner              *deliverypg.Contributor
	renderer           *delivery.TemplateRenderer
	resolver           *capability.KeySet
	policy             *email.RegistrationVerificationPolicy
	endpoint, template string
	templateVersion    uint32
	providerVersion    uint64
	locales            []string
	scopeKey           [32]byte
	timeout            time.Duration
}

// Called synchronously only by the real issuer's original checkpoint transfer.
// The bearer is borrowed for this call; the owned renderer and delivery adapter
// encrypt it before any SQL or sender invocation. Preparation is not queue
// admission or evidence of sending. The existing journal must retain the exact
// checkpoint and final Work must stage it atomically with registration/issuance.
func (r *Repository) prepareSignupDelivery(ctx context.Context, spec email.RegistrationVerificationSpec, token []byte, now time.Time, c signupDeliveryPreparation) (prepared deliverypg.PreparedDelivery, err error) {
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			prepared = deliverypg.PreparedDelivery{}
		}
	}()
	if ctx == nil || !r.configuredWriter() || c.owner == nil || c.renderer == nil || c.resolver == nil || c.policy == nil || c.scopeKey == ([32]byte{}) || c.templateVersion == 0 || c.providerVersion == 0 || !reauthenticationText(c.template, 128) || !reauthenticationText(c.endpoint, 2048) || len(c.locales) == 0 || len(c.locales) > 16 || c.timeout <= 0 || c.timeout > 5*time.Second || len(token) == 0 || len(token) > capability.DefaultLimits().MaxTokenBytes || spec.Binding.ValidateFor(passwordSignupOperation()) != nil || now.IsZero() {
		return prepared, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return prepared, err
	}
	endpoint, err := url.Parse(c.endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Opaque != "" || endpoint.Fragment != "" || endpoint.RawFragment != "" {
		return prepared, password.ErrPasswordWork
	}
	query, err := url.ParseQuery(endpoint.RawQuery)
	if _, reserved := query["token"]; err != nil || reserved {
		return prepared, password.ErrPasswordWork
	}
	work, stop := context.WithTimeout(ctx, c.timeout)
	defer stop()
	grant, err := capability.Verify(work, string(token), c.resolver, capability.VerifyOptions{Now: now, Limits: capability.DefaultLimits()})
	if work.Err() != nil {
		return prepared, work.Err()
	}
	if err != nil || c.policy.Authorize(grant, spec, now) != nil {
		return prepared, password.ErrPasswordWork
	}
	// The delivery owner bounds URL variables to 2048 bytes. Check before query
	// escaping or URL rendering, and then check the final encoded representation.
	if len(token) > 2048-len(c.endpoint)-7 {
		return prepared, password.ErrPasswordWork
	}
	query.Set("token", string(token))
	endpoint.RawQuery = query.Encode()
	link := endpoint.String()
	if len(link) > 2048 {
		return prepared, password.ErrPasswordWork
	}
	address := spec.Payload.CanonicalAddress.Record().Value
	frame, err := json.Marshal(struct {
		Binding    identity.CommandBinding
		Target     identity.SubjectID
		Identifier identity.IdentifierID
		Address    string
		Version    uint64
		ExpiresAt  time.Time
	}{spec.Binding, spec.Payload.SubjectID, spec.IdentifierID, address, spec.VerificationVersion, spec.ExpiresAt})
	if err != nil {
		return prepared, password.ErrPasswordWork
	}
	defer clear(frame)
	mac := hmac.New(sha256.New, c.scopeKey[:])
	_, _ = mac.Write([]byte("identity-password-signup-recipient-v1\x00"))
	_, _ = mac.Write(frame)
	recipient := delivery.Recipient{Channel: delivery.ChannelEmail, Address: address, ScopeDigest: hex.EncodeToString(mac.Sum(nil))}
	message := delivery.Message{Purpose: "identity.email.verification-request", Channel: delivery.ChannelEmail, Recipient: recipient, TemplateID: c.template, TemplateVersion: uint64(c.templateVersion), LocaleChain: slices.Clone(c.locales), Variables: []delivery.TemplateVariable{{Name: "link", Kind: "url", URLValue: link, Sensitive: true}}}
	rendered, err := c.renderer.Render(work, message)
	if work.Err() != nil {
		return prepared, work.Err()
	}
	if err != nil {
		return prepared, password.ErrPasswordWork
	}
	prepared, err = c.owner.Prepare(work, spec.Binding, []deliverypg.IntentInput{{Purpose: message.Purpose, SubjectID: spec.Binding.AnonymousFlowID, TemplateID: c.template, TemplateVersion: c.templateVersion, ProviderConfigVersion: c.providerVersion, ExpiresAt: spec.ExpiresAt, Recipient: recipient, Rendered: rendered}})
	if work.Err() != nil {
		return deliverypg.PreparedDelivery{}, work.Err()
	}
	if err != nil {
		return deliverypg.PreparedDelivery{}, password.ErrPasswordWork
	}
	return prepared, nil
}
