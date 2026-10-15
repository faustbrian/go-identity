package magiclinkpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"time"

	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/magiclink"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
)

type requestArtifacts struct {
	issuance                   issuerpg.PreparedIssuance
	delivery                   deliverypg.PreparedDelivery
	issuanceWire, deliveryWire []byte
}

func (p *requestPhase) flowDigest() ([32]byte, error) {
	f, err := p.flow.Bindings()
	if err != nil {
		return [32]byte{}, invalid()
	}
	remember, err := f.Binding.Intent.Remember.Bindings()
	if err != nil {
		return [32]byte{}, invalid()
	}
	i := f.Binding.Intent
	frame, err := json.Marshal(struct {
		ID                               identity.PreAuthTransactionID
		Tenant                           identity.TenantID
		Action, Origin, Callback, Policy string
		PolicyVersion                    uint64
		Nonce                            [32]byte
		Remember                         session.RememberPolicySpec
		Issued, Expires                  time.Time
		Cookie                           session.TokenDigest
		Version                          uint64
	}{f.Binding.ID, i.TenantID, i.Action, i.Origin, i.CallbackURL, i.PolicyID, i.PolicyVersion, i.Nonce, remember, f.Binding.IssuedAt, f.Binding.ExpiresAt, f.Cookie, f.Version})
	defer clear(frame)
	if err != nil {
		return [32]byte{}, invalid()
	}
	k := p.service.config().IntentKey
	m := hmac.New(sha256.New, k[:])
	m.Write([]byte("identity-magic-link-original-flow-v1\x00"))
	m.Write(frame)
	var digest [32]byte
	copy(digest[:], m.Sum(nil))
	return digest, nil
}

func (p *requestPhase) payload(s requestSelection) (capability.Payload, error) {
	spec, ok := p.original.Feature()
	if !ok || s.recipient.Validate() != nil || s.recipient.Query.TenantID != spec.Binding.TenantID || s.recipient.Query.UserID != "" || s.recipient.Query.Kind != identity.IdentifierEmail || s.recipient.Query.Eligibility != kernel.RecipientVerified || s.issued.IsZero() || !s.expires.After(s.issued) || s.expires.Sub(s.issued) > p.service.config().Lifetime {
		return capability.Payload{}, invalid()
	}
	f, err := p.flow.Bindings()
	if err != nil || s.expires.After(f.Binding.ExpiresAt) {
		return capability.Payload{}, invalid()
	}
	flow, err := p.flowDigest()
	if err != nil {
		return capability.Payload{}, err
	}
	r := s.recipient
	c := p.service.config()
	user, identifier, canonical := r.User.ID, r.Identifier.ID, r.Identifier.CanonicalValue
	identifierVersion, verificationVersion := r.Identifier.Version, r.Verification.Version
	identifierAuthority, userAuthority, credentialAuthority, factor := r.IdentifierAuthorityVersion, r.UserAuthorityVersion, r.CredentialAuthorityVersion, s.factor
	intent := "signin-only"
	var creationDigest [32]byte
	if s.prospective != nil {
		// Prospective versions describe the fixed creation profile, not observed
		// account or factor authority. Never manufacture a verified RecipientRecord
		// for a user that does not exist. The native request/consume fences own
		// current collision policy and the eventual protected creation.
		creation := s.prospective
		expected := spec.Binding
		expected.AnonymousFlowID, expected.OperationID, expected.UserID = "", "identity.user.create", creation.Creation.Binding.UserID
		expected.SchemaID, expected.SchemaVersion = creation.Creation.Binding.SchemaID, creation.Creation.Binding.SchemaVersion
		if p.request.Intent != magiclink.SignupIfAllowed || !r.Suppressed || s.factor != 0 || creation.Creation.Binding != expected || creation.Identifier.CanonicalValue != r.Query.CanonicalValue {
			return capability.Payload{}, invalid()
		}
		creationDigest, err = kernel.MagicLinkRegistrationDigest(*creation)
		if err != nil {
			return capability.Payload{}, err
		}
		user, identifier, canonical = creation.Creation.Binding.UserID, creation.Identifier.ID, creation.Identifier.CanonicalValue
		identifierVersion, verificationVersion, identifierAuthority, userAuthority, credentialAuthority, factor = 1, 1, 1, 1, 1, 1
		intent = "signup-if-allowed"
	} else if r.Suppressed || factor == 0 || p.request.Intent != magiclink.SignInOnly && p.request.Intent != magiclink.SignupIfAllowed {
		return capability.Payload{}, invalid()
	}
	payload := capability.Payload{Version: 1, Issuer: c.IssuerURL, Audiences: []string{c.Issuer.Audience}, Subject: string(user), Tenant: string(spec.Binding.TenantID), Resource: "identity.magiclink/" + string(identifier), Operation: "identity.magic-link.consume", CorrelationID: string(spec.Binding.CommandID), IssuedAt: s.issued, NotBefore: s.issued, ExpiresAt: s.expires, MaxUses: 1, Caveats: map[string]string{
		"magiclink.identifier":                   string(identifier),
		"magiclink.identifier-version":           strconv.FormatUint(identifierVersion, 10),
		"magiclink.verification-version":         strconv.FormatUint(verificationVersion, 10),
		"magiclink.identifier-authority-version": strconv.FormatUint(identifierAuthority, 10),
		"magiclink.user-authority-version":       strconv.FormatUint(userAuthority, 10),
		"magiclink.credential-authority-version": strconv.FormatUint(credentialAuthority, 10),
		"magiclink.canonical-email":              canonical,
		"magiclink.callback":                     p.request.Callback,
		"magiclink.intent":                       intent,
		"magiclink.factor-version":               strconv.FormatUint(factor, 10),
		"magiclink.flow":                         string(f.Binding.ID),
		"magiclink.flow-binding":                 hex.EncodeToString(flow[:]),
		"magiclink.profile":                      hex.EncodeToString(p.service.configuration[:]),
	}}
	if s.prospective != nil {
		payload.Caveats["magiclink.prospective"] = "1"
		payload.Caveats["magiclink.creation-digest"] = hex.EncodeToString(creationDigest[:])
		payload.Caveats["magiclink.email-policy-version"] = strconv.FormatUint(s.prospective.EmailPossessionPolicyVersion, 10)
	}
	scope, err := issuerpg.MagicLinkScopeFromPayload(payload)
	if err != nil {
		return capability.Payload{}, err
	}
	digest := scope.Digest()
	payload.Caveats["magiclink.supersession"] = hex.EncodeToString(digest[:])
	return payload, nil
}

// Generation runs only after the journal acknowledges ownership. No SQL or
// sender runs here: issuer custody is transferred once into the real template
// renderer and encrypted delivery owner, then both original checkpoints are
// retained together. Failure disposes unpublished custody, never reveals it.
func (p *requestPhase) generateDelivery(ctx context.Context, generation uint64, a risk.AuthenticationAdmission) (out requestArtifacts, err error) {
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			_ = out.issuance.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { return nil })
			clear(out.issuanceWire)
			clear(out.deliveryWire)
			out = requestArtifacts{}
		}
	}()
	if ctx == nil || generation == 0 || a.CheckAt(ctx, time.Now().UTC()) != nil {
		return out, invalid()
	}
	spec, ok := p.original.Feature()
	if !ok {
		return out, invalid()
	}
	b := spec.Binding
	payload, err := p.payload(p.selected)
	if err != nil {
		return out, err
	}
	c := p.service.config()
	if p.selected.prospective != nil && c.Possession.Version() != p.selected.prospective.EmailPossessionPolicyVersion {
		return out, invalid()
	}
	work, stop := context.WithTimeout(ctx, c.Delivery.Timeout)
	defer stop()
	if p.selected.prospective != nil {
		out.issuance, err = p.service.issuer.PrepareMagicLinkProspectiveRecipient(work, b, identity.UserID(payload.Subject), payload)
	} else {
		out.issuance, err = p.service.issuer.PrepareMagicLinkRecipient(work, b, p.selected.recipient.User.ID, payload)
	}
	if err != nil {
		return out, err
	}
	out.issuanceWire, err = p.service.codec.CheckpointPreparation(work, out.issuance, generation, func(ctx context.Context, index uint16, token []byte) error {
		if index != 0 || len(out.deliveryWire) != 0 {
			return invalid()
		}
		grant, e := capability.Verify(ctx, string(token), c.Issuer.Crypto.Resolver, capability.VerifyOptions{Issuer: c.Issuer.Crypto.Issuer, Now: time.Now().UTC(), Limits: c.Issuer.Crypto.Limits})
		if e != nil {
			return invalid()
		}
		actual := grant.Payload()
		expected := payload
		expected.ID = actual.ID
		if actual.ID == "" || !reflect.DeepEqual(actual, expected) {
			return invalid()
		}
		if p.selected.prospective != nil {
			original, e := p.possessionSpec(p.selected)
			if e != nil || c.Possession.Authorize(grant, original, time.Now().UTC()) != nil {
				return invalid()
			}
		}
		// Fragments are not sent by browsers in landing requests or Referer.
		// The explicit consumer must POST the proof; inspection never consumes.
		if len(token) > 2048-len(c.Delivery.Endpoint)-7 {
			return invalid()
		}
		u, e := url.Parse(c.Delivery.Endpoint)
		if e != nil {
			return invalid()
		}
		u.Fragment = "token=" + string(token)
		link := u.String()
		if len(link) > 2048 {
			return invalid()
		}
		frame, e := json.Marshal(struct {
			Binding       identity.CommandBinding
			Address, Flow string
		}{b, payload.Caveats["magiclink.canonical-email"], payload.Caveats["magiclink.flow-binding"]})
		defer clear(frame)
		if e != nil {
			return invalid()
		}
		m := hmac.New(sha256.New, c.Delivery.ScopeKey[:])
		m.Write([]byte("identity-magic-link-recipient-v1\x00"))
		m.Write(frame)
		recipient := delivery.Recipient{Channel: delivery.ChannelEmail, Address: payload.Caveats["magiclink.canonical-email"], ScopeDigest: hex.EncodeToString(m.Sum(nil))}
		message := delivery.Message{Purpose: b.OperationID, Channel: delivery.ChannelEmail, Recipient: recipient, TemplateID: c.Delivery.TemplateID, TemplateVersion: uint64(c.Delivery.TemplateVersion), LocaleChain: slices.Clone(c.Delivery.Locales), Variables: []delivery.TemplateVariable{{Name: "link", Kind: "url", URLValue: link, Sensitive: true}}}
		rendered, e := c.Delivery.Renderer.Render(ctx, message)
		if e != nil {
			return invalid()
		}
		out.delivery, e = c.Delivery.Owner.Prepare(ctx, b, []deliverypg.IntentInput{{Purpose: b.OperationID, SubjectID: b.AnonymousFlowID, TemplateID: c.Delivery.TemplateID, TemplateVersion: c.Delivery.TemplateVersion, ProviderConfigVersion: c.Delivery.ProviderVersion, ExpiresAt: payload.ExpiresAt, Recipient: recipient, Rendered: rendered}})
		if e != nil {
			return e
		}
		out.deliveryWire, e = c.Delivery.Owner.CheckpointPreparation(ctx, out.delivery, generation)
		return e
	})
	if work.Err() != nil {
		return out, work.Err()
	}
	if err != nil {
		return out, err
	}
	if len(out.issuanceWire) == 0 || len(out.deliveryWire) == 0 || a.CheckAt(work, time.Now().UTC()) != nil {
		return out, invalid()
	}
	return out, nil
}
