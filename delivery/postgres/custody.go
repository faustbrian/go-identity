// Package postgres implements durable identity delivery. Queue persistence and
// processing are under development; the private custody codec grants no send,
// workflow authorization, transaction or queue admission authority.
package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

const custodyHeader = "IDEP1"
const maximumCustody = 524288
const maximumPlaintext = 262144

// This immutable scope is supplied only by the owned workflow admission path.
// Shape validation and possession of it do not establish authorization.
type payloadBinding struct {
	Deployment       string
	Command          identity.CommandBinding
	Intent           identitypostgres.DeliveryIntentPlan
	Provider         string
	PolicyVersion    uint64
	DigestKeyVersion uint32
	NoOpEquivalent   bool
}

type payload struct {
	Recipient delivery.Recipient
	Rendered  delivery.RenderedMessage
}

// Explicit persistence DTO avoids invoking the core's forbidden diagnostic
// serialization. It exists only in bounded memory around envelope encryption.
type payloadWire struct {
	Channel                                                     delivery.Channel
	Address, RecipientScope, Locale, Subject, Body, ContentType string
}

func (payload) Format(s fmt.State, _ rune)     { _, _ = s.Write([]byte("delivery.postgres(redacted)")) }
func (payloadWire) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("delivery.postgres(redacted)")) }

func (payload) LogValue() slog.Value     { return slog.StringValue("delivery.postgres(redacted)") }
func (payloadWire) LogValue() slog.Value { return slog.StringValue("delivery.postgres(redacted)") }

type payloadCodec struct {
	service *secretenvelope.Service
	keys    map[uint32][32]byte
	timeout time.Duration
}

func (payloadCodec) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("delivery.postgres(redacted)"))
}
func (payloadCodec) LogValue() slog.Value { return slog.StringValue("delivery.postgres(redacted)") }

func newPayloadCodec(service *secretenvelope.Service, keys map[uint32][32]byte, timeout time.Duration) (*payloadCodec, error) {
	if service == nil || len(keys) < 1 || len(keys) > 32 || timeout < time.Second || timeout > 30*time.Second {
		return nil, delivery.ErrInvalidInput
	}
	c := &payloadCodec{service: service, keys: make(map[uint32][32]byte, len(keys)), timeout: timeout}
	for version, key := range keys {
		if version == 0 || key == ([32]byte{}) {
			return nil, delivery.ErrInvalidInput
		}
		c.keys[version] = key
	}
	return c, nil
}

func safeID(s string, optional bool) bool {
	if optional && s == "" {
		return true
	}
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i := range len(s) {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

func custodyContext(b payloadBinding, includeDigest bool) (secretenvelope.Context, error) {
	c, i := b.Command, b.Intent
	anonymous := c.AnonymousFlowID != ""
	// The namespace is authenticated, not inferred from the subject's text.
	// Keep the installed user profile byte-for-byte unchanged for retained data.
	if anonymous {
		if c.UserID != "" || !safeID(c.AnonymousFlowID, false) || c.LinkMode != 0 || i.SubjectID != c.AnonymousFlowID {
			return secretenvelope.Context{}, delivery.ErrInvalidInput
		}
	} else if !safeID(string(c.UserID), false) {
		return secretenvelope.Context{}, delivery.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(c.CommandID)); err != nil {
		return secretenvelope.Context{}, delivery.ErrInvalidInput
	}
	if !safeID(b.Deployment, false) || !safeID(string(c.TenantID), false) || !safeID(string(c.ActorID), false) || !safeID(c.OperationID, false) || !safeID(c.PolicyID, false) || !safeID(c.SchemaID, false) || !safeID(c.CorrelationID, false) || !safeID(c.RecordID, true) || c.PolicyVersion == 0 || c.SchemaVersion == 0 || c.LinkMode > identity.AccountLinkAdministrative || (c.ActorKind != authorization.SubjectUser && c.ActorKind != authorization.SubjectAPIKey && c.ActorKind != authorization.SubjectServiceAccount) || !safeID(i.EffectID, false) || !safeID(i.Purpose, false) || !safeID(i.SubjectID, false) || !safeID(i.TemplateID, false) || !safeID(b.Provider, false) || i.TemplateVersion == 0 || i.ProviderConfigVersion == 0 || b.PolicyVersion == 0 || b.DigestKeyVersion == 0 || i.ExpiresAt.UnixMicro() <= 0 || i.ExpiresAt.Year() > 9999 || i.ExpiresAt.Nanosecond()%1000 != 0 || includeDigest && i.IntentDigest == ([32]byte{}) {
		return secretenvelope.Context{}, delivery.ErrInvalidInput
	}
	values := map[string]string{
		"profile": "identity-delivery-payload-v1", "deployment": b.Deployment,
		"command": string(c.CommandID), "tenant": string(c.TenantID), "user": string(c.UserID), "actor": string(c.ActorID), "actor_kind": string(c.ActorKind),
		"operation": c.OperationID, "command_policy": c.PolicyID, "command_policy_version": strconv.FormatUint(c.PolicyVersion, 10), "command_schema": c.SchemaID, "command_schema_version": strconv.FormatUint(uint64(c.SchemaVersion), 10), "correlation": c.CorrelationID, "record": c.RecordID, "link_mode": strconv.FormatUint(uint64(c.LinkMode), 10),
		"effect": i.EffectID, "effect_index": strconv.FormatUint(uint64(i.EffectIndex), 10), "purpose": i.Purpose, "subject": i.SubjectID, "template": i.TemplateID, "template_version": strconv.FormatUint(uint64(i.TemplateVersion), 10), "provider": b.Provider, "provider_version": strconv.FormatUint(i.ProviderConfigVersion, 10), "delivery_policy": strconv.FormatUint(b.PolicyVersion, 10), "expiry": strconv.FormatInt(i.ExpiresAt.UnixMicro(), 10), "digest_key_version": strconv.FormatUint(uint64(b.DigestKeyVersion), 10), "no_op": strconv.FormatBool(b.NoOpEquivalent),
	}
	if anonymous {
		values["profile"] = "identity-delivery-payload-anonymous-v1"
		values["anonymous_flow"] = c.AnonymousFlowID
	}
	if includeDigest {
		values["intent_digest"] = hex.EncodeToString(i.IntentDigest[:])
	}
	return secretenvelope.NewContext(values)
}

func encodePayload(p payload) ([]byte, error) {
	r := p.Rendered
	if p.Recipient.Validate() != nil || r.Channel != p.Recipient.Channel || len(r.Locale) < 1 || len(r.Locale) > 35 || !safeLocale(r.Locale) || len(r.Subject) > 998 || len(r.Body) < 1 || len(r.Body) > 262144 || len(r.Subject)+len(r.Body) > 262144 || !utf8.ValidString(r.Subject) || !utf8.ValidString(r.Body) || (r.ContentType != "text/plain" && r.ContentType != "text/html") || r.Channel == delivery.ChannelSMS && (r.Subject != "" || r.ContentType != "text/plain") {
		return nil, delivery.ErrInvalidInput
	}
	for _, ch := range r.Subject {
		if ch < 32 || ch == 127 {
			return nil, delivery.ErrInvalidInput
		}
	}
	wire, err := json.Marshal(payloadWire{r.Channel, p.Recipient.Address, p.Recipient.ScopeDigest, r.Locale, r.Subject, r.Body, r.ContentType})
	if err != nil || len(wire) > maximumPlaintext {
		clear(wire)
		return nil, delivery.ErrInvalidInput
	}
	return wire, nil
}

func safeLocale(s string) bool {
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := range len(s) {
		b := s[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
			continue
		}
		if b != '-' || i > 0 && s[i-1] == '-' {
			return false
		}
	}
	return true
}

// Domain-separated HMAC binds length-framed owned context and sensitive bytes.
// It is a confidential input fingerprint/attestation, never another authority
// ledger or an encryption algorithm. Ciphertext randomness is not logical input.
func custodyMAC(key [32]byte, domain string, aad, data []byte) [32]byte {
	h := hmac.New(sha256.New, key[:])
	_, _ = h.Write([]byte(domain))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(aad)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(aad)
	binary.BigEndian.PutUint64(size[:], uint64(len(data)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(data)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func (c *payloadCodec) callContext(ctx context.Context, expiry time.Time) (context.Context, context.CancelFunc, error) {
	if c == nil || c.service == nil || ctx == nil {
		return nil, nil, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	now := time.Now()
	if !expiry.After(now) {
		return nil, nil, delivery.ErrExpired
	}
	deadline := now.Add(c.timeout)
	if expiry.Before(deadline) {
		deadline = expiry
	}
	w, stop := context.WithDeadline(ctx, deadline)
	return w, stop, nil
}

func (c *payloadCodec) seal(ctx context.Context, b payloadBinding, p payload, keyID string) (bound payloadBinding, custody identitypostgres.DeliveryEnvelope, err error) {
	w, stop, err := c.callContext(ctx, b.Intent.ExpiresAt)
	if err != nil {
		return bound, custody, err
	}
	defer stop()
	defer func() {
		if recover() != nil {
			bound = payloadBinding{}
			custody = identitypostgres.DeliveryEnvelope{}
			err = delivery.ErrUnavailable
		}
	}()
	if !safeID(keyID, false) {
		return bound, custody, delivery.ErrInvalidInput
	}
	key, ok := c.keys[b.DigestKeyVersion]
	if !ok {
		return bound, custody, delivery.ErrUnavailable
	}
	aad, err := custodyContext(b, false)
	if err != nil {
		return bound, custody, err
	}
	plain, err := encodePayload(p)
	if err != nil {
		return bound, custody, err
	}
	defer clear(plain)
	b.Intent.IntentDigest = custodyMAC(key, "identity-delivery-logical-v1", aad.AdditionalData(), plain)
	aad, err = custodyContext(b, true)
	if err != nil {
		return bound, custody, err
	}
	envelope, err := c.service.Encrypt(w, secretenvelope.EncryptRequest{Plaintext: plain, KeyReference: keyID, Context: aad})
	if w.Err() != nil {
		return bound, custody, w.Err()
	}
	if err != nil {
		return bound, custody, delivery.ErrUnavailable
	}
	data, err := envelope.MarshalBinary()
	if err != nil || envelope.KeyReference() != keyID || len(data) > maximumCustody-9-32 {
		return bound, custody, delivery.ErrUnavailable
	}
	wire := make([]byte, 9, 9+len(data)+32)
	copy(wire, custodyHeader)
	binary.BigEndian.PutUint32(wire[5:9], b.DigestKeyVersion)
	wire = append(wire, data...)
	mac := custodyMAC(key, "identity-delivery-custody-v1", aad.AdditionalData(), wire)
	wire = append(wire, mac[:]...)
	return b, identitypostgres.DeliveryEnvelope{EffectIndex: b.Intent.EffectIndex, KeyID: keyID, Ciphertext: wire}, nil
}

// Verification is entirely local, before any SQL; KMS and provider callbacks
// must never run while the original domain transaction holds locks.
func (c *payloadCodec) verify(b payloadBinding, v identitypostgres.DeliveryEnvelope) error {
	if c == nil || len(v.Ciphertext) < 9+32 || len(v.Ciphertext) > maximumCustody || string(v.Ciphertext[:5]) != custodyHeader || binary.BigEndian.Uint32(v.Ciphertext[5:9]) != b.DigestKeyVersion || v.EffectIndex != b.Intent.EffectIndex || !safeID(v.KeyID, false) {
		return delivery.ErrInvalidInput
	}
	key, ok := c.keys[b.DigestKeyVersion]
	if !ok {
		return delivery.ErrUnavailable
	}
	aad, err := custodyContext(b, true)
	if err != nil {
		return err
	}
	end := len(v.Ciphertext) - 32
	mac := custodyMAC(key, "identity-delivery-custody-v1", aad.AdditionalData(), v.Ciphertext[:end])
	if !hmac.Equal(mac[:], v.Ciphertext[end:]) {
		return delivery.ErrForbidden
	}
	envelope, err := secretenvelope.ParseEnvelope(v.Ciphertext[9:end])
	if err != nil || envelope.KeyReference() != v.KeyID {
		return delivery.ErrForbidden
	}
	return nil
}

// Open is used outside the lease transaction and only before a bounded sender
// invocation. Its caller owns returned sensitive strings for that invocation.
func (c *payloadCodec) open(ctx context.Context, b payloadBinding, v identitypostgres.DeliveryEnvelope) (result payload, err error) {
	w, stop, err := c.callContext(ctx, b.Intent.ExpiresAt)
	if err != nil {
		return result, err
	}
	defer stop()
	defer func() {
		if recover() != nil {
			result = payload{}
			err = delivery.ErrUnavailable
		}
	}()
	if err = c.verify(b, v); err != nil {
		return result, err
	}
	aad, _ := custodyContext(b, true)
	envelope, _ := secretenvelope.ParseEnvelope(v.Ciphertext[9 : len(v.Ciphertext)-32])
	plain, err := c.service.Decrypt(w, secretenvelope.DecryptRequest{Envelope: envelope, Context: aad})
	defer clear(plain)
	if w.Err() != nil {
		return result, w.Err()
	}
	if err != nil {
		return result, delivery.ErrUnavailable
	}
	if len(plain) < 1 || len(plain) > maximumPlaintext {
		return result, delivery.ErrInvalidInput
	}
	var decoded payloadWire
	reader := json.NewDecoder(bytes.NewReader(plain))
	reader.DisallowUnknownFields()
	if reader.Decode(&decoded) != nil {
		return result, delivery.ErrInvalidInput
	}
	p := payload{Recipient: delivery.Recipient{Channel: decoded.Channel, Address: decoded.Address, ScopeDigest: decoded.RecipientScope}, Rendered: delivery.RenderedMessage{Channel: decoded.Channel, Locale: decoded.Locale, Subject: decoded.Subject, Body: decoded.Body, ContentType: decoded.ContentType}}
	canonical, err := encodePayload(p)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plain) {
		return result, delivery.ErrInvalidInput
	}
	logical, _ := custodyContext(b, false)
	digest := custodyMAC(c.keys[b.DigestKeyVersion], "identity-delivery-logical-v1", logical.AdditionalData(), plain)
	if !hmac.Equal(digest[:], b.Intent.IntentDigest[:]) {
		return result, delivery.ErrForbidden
	}
	return p, nil
}
