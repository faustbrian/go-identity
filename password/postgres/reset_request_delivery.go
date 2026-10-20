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

	auth "github.com/faustbrian/go-authentication/v2"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// Invocation-only native request composition. No caller selects a template,
// provider revision, locale chain, signing key or bearer-bearing endpoint.
type resetRequestDeliveryPreparation struct {
	issuer             *issuerpg.Issuer
	codec              *issuerpg.IssuancePreparationCodec
	profile            password.ResetProfile
	owner              *deliverypg.Contributor
	renderer           *delivery.TemplateRenderer
	resolver           *capability.KeySet
	endpoint, template string
	templateVersion    uint32
	providerVersion    uint64
	locales            []string
	scopeKey           [32]byte
	timeout            time.Duration
}

type resetRequestDelivery struct {
	issuance                   issuerpg.PreparedIssuance
	delivery                   deliverypg.PreparedDelivery
	issuanceWire, deliveryWire []byte
}

// Private scalar projection is confined to the recipient HMAC frame. The
// public intent deliberately rejects generic JSON/log serialization.
type resetRecipientOrigin password.ResetGrantSpec

func resetRequestOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.reset-request", SchemaID: "password-reset-request", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// Only acknowledged first generation may call this, after current primary
// account/credential/factor selection and counted risk admission. It transfers
// the issuer's bearer exactly once into rendering/encryption and the existing
// issuer checkpoint. It never returns a bearer, calls a sender or opens SQL.
// Both checkpoints must be retained in the existing original output journal,
// then restored and staged together in its sole protected Work. A prepared
// result is not evidence of current authority, commitment or delivery.
func (r *Repository) generateResetRequestDelivery(ctx context.Context, b identity.CommandBinding, origin password.ResetGrantSpec, recipient kernel.RecipientRecord, admission risk.AuthenticationAdmission, generation uint64, c resetRequestDeliveryPreparation) (out resetRequestDelivery, err error) {
	return r.generateResetRequestDeliveryMode(ctx, b, origin, recipient, admission, generation, c, false)
}

// The exact phone owner stages this alongside the original SMS at index zero.
// This selects only canonical grant/rendering custody, not risk permission,
// current factor admission, the protected transaction or actual dispatch.
func (r *Repository) generatePhoneResetRequestDelivery(ctx context.Context, b identity.CommandBinding, origin password.ResetGrantSpec, recipient kernel.RecipientRecord, generation uint64, c resetRequestDeliveryPreparation) (resetRequestDelivery, error) {
	return r.generateResetRequestDeliveryMode(ctx, b, origin, recipient, risk.AuthenticationAdmission{}, generation, c, true)
}

func phoneResetRequestOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-request", SchemaID: "identity.phone.password-reset-request.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// Share the actual canonical issuer, one-transfer checkpoint, local rendering
// and encrypted delivery engine. The closed selector preserves installed email
// bytes and anonymous recipient override; phone uses a known-user binding and
// must never gain that override or occupy the original code's delivery index.
func (r *Repository) generateResetRequestDeliveryMode(ctx context.Context, b identity.CommandBinding, origin password.ResetGrantSpec, recipient kernel.RecipientRecord, admission risk.AuthenticationAdmission, generation uint64, c resetRequestDeliveryPreparation, phone bool) (out resetRequestDelivery, err error) {
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			// If failure preceded checkpoint transfer, dispose of unpublished
			// custody. After transfer this is already terminal, never a reveal.
			_ = out.issuance.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { return nil })
			clear(out.issuanceWire)
			clear(out.deliveryWire)
			out = resetRequestDelivery{}
		}
	}()
	op, kind, channel := resetRequestOperation(), identity.IdentifierEmail, delivery.ChannelEmail
	subject, effect := b.AnonymousFlowID, uint16(0)
	if phone {
		op, kind, channel = phoneResetRequestOperation(), identity.IdentifierPhone, delivery.ChannelSMS
		subject, effect = string(b.UserID), 1
		if origin.RecoveryPath != auth.RecoveryPathPhone || b.UserID == "" || b.UserID != origin.UserID || b.RecordID != string(b.CommandID) || origin.Phone.OTPChallengeID != string(b.CommandID) || origin.Phone.VerificationVersion != recipient.Verification.Version {
			return out, password.ErrPasswordWork
		}
	}
	if ctx == nil || !r.configuredWriter() || b.ValidateFor(op) != nil || c.issuer == nil || c.codec == nil || c.owner == nil || c.renderer == nil || c.resolver == nil || c.scopeKey == ([32]byte{}) || c.templateVersion == 0 || c.providerVersion == 0 || !reauthenticationText(c.template, 128) || len(c.locales) == 0 || len(c.locales) > 16 || c.timeout <= 0 || c.timeout > 5*time.Second || generation == 0 {
		return out, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if recipient.Validate() != nil || recipient.Suppressed || recipient.Query.TenantID != b.TenantID || recipient.Query.UserID != "" || recipient.Query.Kind != kind || recipient.Query.Eligibility != kernel.RecipientVerified || origin.OriginCommandID != b.CommandID || origin.TenantID != b.TenantID || origin.UserID != recipient.User.ID || origin.UserAuthorityVersion != recipient.UserAuthorityVersion || origin.CredentialAuthorityVersion != recipient.CredentialAuthorityVersion || origin.IdentifierID != recipient.Identifier.ID || origin.IdentifierVersion != recipient.Identifier.Version || origin.FactorVersion == 0 {
		return out, password.ErrPasswordWork
	}
	scope := admission.Prepared().Scope
	if !phone && (scope.Tenant != string(b.TenantID) || scope.Operation != risk.Action(b.OperationID) || scope.Attempt != string(b.CommandID) || admission.CheckAt(ctx, time.Now().UTC()) != nil) {
		return out, password.ErrPasswordWork
	}
	endpoint, err := url.Parse(c.endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Opaque != "" || endpoint.Fragment != "" || endpoint.RawFragment != "" || !reauthenticationText(c.endpoint, 2048) {
		return out, password.ErrPasswordWork
	}
	query, err := url.ParseQuery(endpoint.RawQuery)
	if _, reserved := query["token"]; err != nil || reserved {
		return out, password.ErrPasswordWork
	}
	payload, err := c.profile.Payload(origin)
	if err != nil {
		return out, password.ErrPasswordWork
	}
	work, stop := context.WithTimeout(ctx, c.timeout)
	defer stop()
	if phone {
		out.issuance, err = c.issuer.Prepare(work, b, []capability.Payload{payload})
	} else {
		out.issuance, err = c.issuer.PrepareResetRecipient(work, b, origin.UserID, payload)
	}
	if err != nil {
		return out, err
	}
	out.issuanceWire, err = c.codec.CheckpointPreparation(work, out.issuance, generation, func(ctx context.Context, index uint16, token []byte) error {
		if index != 0 || len(out.deliveryWire) != 0 {
			return password.ErrPasswordWork
		}
		grant, err := capability.Verify(ctx, string(token), c.resolver, capability.VerifyOptions{Issuer: payload.Issuer, Now: time.Now().UTC(), Limits: capability.DefaultLimits()})
		if err != nil || c.profile.Authorize(grant, origin, time.Now().UTC()) != nil {
			return password.ErrPasswordWork
		}
		// Bound URL expansion before encoding; the delivery template owner
		// enforces the same fixed 2048-byte URL-variable ceiling.
		if len(token) > 2048-len(c.endpoint)-7 {
			return password.ErrPasswordWork
		}
		query.Set("token", string(token))
		endpoint.RawQuery = query.Encode()
		link := endpoint.String()
		if len(link) > 2048 {
			return password.ErrPasswordWork
		}
		var frame []byte
		domain := "identity-password-reset-recipient-v1\x00"
		if phone {
			// The canonical payload already owns every phone/factor caveat. Keep
			// its sensitive scalar frame confined to this local HMAC rather than
			// weakening PhoneResetBinding's public serialization prohibition.
			frame, err = json.Marshal(struct {
				Binding identity.CommandBinding
				Payload capability.Payload
				Address string
			}{b, payload, recipient.Identifier.CanonicalValue})
			domain = "identity-phone-reset-recipient-v1\x00"
		} else {
			frame, err = json.Marshal(struct {
				Binding identity.CommandBinding
				Origin  resetRecipientOrigin
				Address string
			}{b, resetRecipientOrigin(origin), recipient.Identifier.CanonicalValue})
		}
		if err != nil {
			return password.ErrPasswordWork
		}
		defer clear(frame)
		mac := hmac.New(sha256.New, c.scopeKey[:])
		_, _ = mac.Write([]byte(domain))
		_, _ = mac.Write(frame)
		selected := delivery.Recipient{Channel: channel, Address: recipient.Identifier.CanonicalValue, ScopeDigest: hex.EncodeToString(mac.Sum(nil))}
		message := delivery.Message{Purpose: b.OperationID, Channel: channel, Recipient: selected, TemplateID: c.template, TemplateVersion: uint64(c.templateVersion), LocaleChain: slices.Clone(c.locales), Variables: []delivery.TemplateVariable{{Name: "link", Kind: "url", URLValue: link, Sensitive: true}}}
		rendered, err := c.renderer.Render(ctx, message)
		if err != nil {
			return password.ErrPasswordWork
		}
		out.delivery, err = c.owner.Prepare(ctx, b, []deliverypg.IntentInput{{EffectIndex: effect, Purpose: b.OperationID, SubjectID: subject, TemplateID: c.template, TemplateVersion: c.templateVersion, ProviderConfigVersion: c.providerVersion, ExpiresAt: origin.ExpiresAt, Recipient: selected, Rendered: rendered}})
		if err != nil {
			return password.ErrPasswordWork
		}
		out.deliveryWire, err = c.owner.CheckpointPreparation(ctx, out.delivery, generation)
		return err
	})
	if work.Err() != nil {
		return out, work.Err()
	}
	if err != nil || len(out.issuanceWire) == 0 || len(out.deliveryWire) == 0 || !phone && admission.CheckAt(work, time.Now().UTC()) != nil {
		return out, password.ErrPasswordWork
	}
	return out, nil
}
