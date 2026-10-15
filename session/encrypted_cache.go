package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// EncryptedCacheConfig binds a deployment's encrypted positive-cache profile.
// Issuer and Environment are canonical visible ASCII identifiers (1..256 and
// 1..128 bytes); DeploymentEpoch is positive and changes on compromise or cache
// reset. KeyReference names the active wrapping key; retained read keys belong
// to the envelope provider. MaximumAge is 1ms..5m, never renewed authority.
// MaximumBytes is the binary envelope limit, 256..32768, checked before parsing.
// Browser composition must separately bound base64/cookie framing and attributes.
type EncryptedCacheConfig struct {
	Issuer, Environment string
	DeploymentEpoch     uint64
	KeyReference        string
	MaximumAge          time.Duration
	MaximumBytes        int
}

// EncryptedCacheCodec encrypts the complete owned session projection and its
// original admission deadline. It is safe for concurrent calls with concurrent
// safe dependencies. It owns no store, resource, goroutine or independent
// authority vector. Envelope keys are trusted deployment credentials, not user
// callbacks or client-selected keys. Provider calls share the session service's
// bounded context and must honor cancellation. Retain wrapping keys only as long
// as their cache entries remain eligible; removal fails closed or uses primary.
// This is a stateful cache codec, not fully stateless authentication or HTTP.
type EncryptedCacheCodec struct {
	service *SessionService
	crypto  *envelope.Service
	config  EncryptedCacheConfig
}

// NewEncryptedCacheCodec freezes explicit encrypted-cache configuration without
// IO. Only the owning SessionService may mint payloads. Another process with the
// same trusted profile/keys may restore them, without restarting validity.
func NewEncryptedCacheCodec(service *SessionService, crypto *envelope.Service, config EncryptedCacheConfig) (*EncryptedCacheCodec, error) {
	if service == nil || crypto == nil || !authorityKey(config.Issuer, 256) || !authorityKey(config.Environment, 128) || config.DeploymentEpoch == 0 || !authorityKey(config.KeyReference, 256) || config.MaximumAge < time.Millisecond || config.MaximumAge > 5*time.Minute || config.MaximumBytes < 256 || config.MaximumBytes > 32768 {
		return nil, ErrInvalidInput
	}
	return &EncryptedCacheCodec{service, crypto, config}, nil
}

// Seal returns caller-owned authenticated ciphertext, never a raw bearer or
// plaintext projection. Only genuine unchanged same-service admission can seal.
// Cached/promoted results retain their earlier deadline. Crypto work is bounded;
// expired, canceled or backward-clock work returns no payload. Errors redact
// all provider diagnostics. Explicit bytes are for trusted cache persistence;
// never log them. Transport remains dependent on the original opaque credential.
func (c *EncryptedCacheCodec) Seal(ctx context.Context, result GetResult) (out []byte, err error) {
	defer func() {
		if recover() != nil {
			out, err = nil, ErrUnavailable
		}
	}()
	if c == nil || ctx == nil {
		return nil, ErrInvalidInput
	}
	bounded, stop := context.WithTimeout(ctx, c.service.config.MaximumDuration)
	defer stop()
	if bounded.Err() != nil {
		return nil, sessionReadFailure(bounded)
	}
	cached, e := c.service.CacheAdmission(result, c.config.MaximumAge)
	if e != nil {
		return nil, e
	}
	result = cached.state.result
	p := result.validity
	storedAt := c.service.config.Clock.Now()
	if result.ValidateAt(storedAt) != nil {
		return nil, ErrUnauthenticated
	}
	spec, _ := result.Session.Bindings()
	remember, _ := spec.Remember.Bindings()
	authority, _ := spec.Authority.Bindings()
	record := cacheRecord{Schema: 1, Session: cacheSession{spec.SessionID, spec.FamilyID, spec.TenantID, spec.UserID, spec.Audience, spec.Version, spec.FamilyVersion, remember, authority, spec.Lookup, spec.Authentication, spec.IssuedAt.UTC(), spec.LastActivityAt.UTC()}, Transport: p.transport, NeedsRefresh: p.refresh, Eligible: p.eligible.UTC(), AcceptedAt: p.acceptedAt.UTC(), Until: p.until.UTC(), StoredAt: storedAt.UTC()}
	if state := result.Session.CSRFState(); state.state != nil {
		value := state.state.spec
		record.Schema, record.CSRF = 2, &value
	}
	if metadata := result.Session.OTPAuthentication(); metadata.state != nil {
		value := *metadata.state
		record.OTP = &value
		record.Schema += 2
	}
	if metadata := result.Session.MagicLinkAuthentication(); metadata.state != nil {
		value := *metadata.state
		record.MagicLink = &value
		record.Schema += 6
	}
	if metadata := result.Session.MFAAuthentication(); metadata.state != nil {
		value := *metadata.state
		record.MFA = &value
		if spec.Authentication.Kind == AuthenticationVerified {
			// Password-primary MFA has its own closed schema; do not collide
			// with the legacy OTP schemas or silently drop factor provenance.
			record.Schema += 10
		} else {
			record.Schema += 2
		}
	}
	if continuation, ok := result.Session.CredentialContinuation(); ok {
		record.Continuation = &continuation
		record.Schema += 4
	}
	record.Session.Authentication.Proof.IssuedAt = record.Session.Authentication.Proof.IssuedAt.UTC()
	record.Session.Authentication.Proof.ExpiresAt = record.Session.Authentication.Proof.ExpiresAt.UTC()
	record.Session.Authentication.AnonymousAt = record.Session.Authentication.AnonymousAt.UTC()
	plaintext, e := json.Marshal(record)
	if e != nil || len(plaintext) > c.config.MaximumBytes {
		return nil, ErrInvalidInput
	}
	defer clear(plaintext)
	aad, e := c.additionalData(spec.TenantID)
	if e != nil {
		return nil, ErrInvalidInput
	}
	encrypted, e := c.crypto.Encrypt(bounded, envelope.EncryptRequest{Plaintext: plaintext, KeyReference: c.config.KeyReference, Context: aad})
	if e != nil {
		return nil, cacheCryptoError(bounded, e)
	}
	out, e = encrypted.MarshalBinary()
	if e != nil || len(out) > c.config.MaximumBytes {
		return nil, ErrInvalidInput
	}
	now := c.service.config.Clock.Now()
	if bounded.Err() != nil {
		return nil, sessionReadFailure(bounded)
	}
	if !validTime(now) || now.Before(storedAt) {
		return nil, ErrUnavailable
	}
	if result.ValidateAt(now) != nil {
		return nil, ErrUnauthenticated
	}
	return out, nil
}

// Get authenticates a bounded encrypted projection then reuses only exact
// tenant/digest/transport custody. Corrupt, foreign, stale or absent entries use
// bounded primary Get. A provider outage may use primary, never stale evidence.
// Every restored result retains the complete original authority/lifetime and
// exclusive source deadline, including after restarts, copies and key rotation.
// Matching ciphertext alone does not authenticate without the original bearer.
func (c *EncryptedCacheCodec) Get(ctx context.Context, request GetRequest, blob []byte) (out GetResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = GetResult{}, ErrUnavailable
		}
	}()
	if c == nil || ctx == nil || !authorityKey(string(request.TenantID), 128) || request.Credential.token.state == nil || (request.Credential.kind != CredentialCookie && request.Credential.kind != CredentialBearer) {
		return out, ErrInvalidInput
	}
	bounded, stop := context.WithTimeout(ctx, c.service.config.MaximumDuration)
	defer stop()
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	before := c.service.config.Clock.Now()
	if !validTime(before) {
		return out, ErrUnavailable
	}
	cached := CachedAdmission{}
	if len(blob) > 0 && len(blob) <= c.config.MaximumBytes {
		encrypted, e := envelope.ParseEnvelope(blob)
		if e == nil {
			aad, e := c.additionalData(request.TenantID)
			if e != nil {
				return out, ErrInvalidInput
			}
			plaintext, e := c.crypto.Decrypt(bounded, envelope.DecryptRequest{Envelope: encrypted, Context: aad})
			if e != nil {
				if bounded.Err() != nil || errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
					return out, cacheCryptoError(bounded, e)
				}
			} else {
				defer clear(plaintext)
				cached = c.restore(plaintext, request.TenantID)
				clear(plaintext)
			}
		}
	}
	now := c.service.config.Clock.Now()
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	if !validTime(now) || now.Before(before) {
		return out, ErrUnavailable
	}
	return c.service.GetCached(bounded, request, cached)
}

// Closed, canonical framing prevents JSON's permissive duplicate/null/short-array
// decoding from manufacturing missing dimensions. There is one authority value,
// inside Session; admission timestamps are provenance, not another version vector.
type cacheSession struct {
	SessionID, FamilyID      string
	TenantID                 identity.TenantID
	UserID                   identity.UserID
	Audience                 string
	Version, FamilyVersion   uint64
	Remember                 RememberPolicySpec
	Authority                AuthoritySnapshotSpec
	Lookup                   TokenDigest
	Authentication           AuthenticationMetadata
	IssuedAt, LastActivityAt time.Time
}
type cacheRecord struct {
	Schema                                uint32
	Session                               cacheSession
	Transport                             CredentialKind
	NeedsRefresh                          bool
	Eligible, AcceptedAt, Until, StoredAt time.Time
	CSRF                                  *CSRFStateSpec               `json:",omitempty"`
	OTP                                   *OTPAuthenticationSpec       `json:",omitempty"`
	MagicLink                             *MagicLinkAuthenticationSpec `json:",omitempty"`
	MFA                                   *MFAAuthenticationSpec       `json:",omitempty"`
	Continuation                          *CredentialContinuationSpec  `json:",omitempty"`
}

func (c *EncryptedCacheCodec) restore(plaintext []byte, tenant identity.TenantID) CachedAdmission {
	if len(plaintext) == 0 || len(plaintext) > c.config.MaximumBytes {
		return CachedAdmission{}
	}
	var r cacheRecord
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil {
		return CachedAdmission{}
	}
	canonical, e := json.Marshal(r)
	if e != nil {
		return CachedAdmission{}
	}
	defer clear(canonical)
	validSchema := r.MFA == nil && (r.MagicLink == nil && ((r.Schema == 1 && r.CSRF == nil && r.OTP == nil && r.Continuation == nil && r.Session.Authentication.Kind == AuthenticationVerified) ||
		(r.Schema == 2 && r.CSRF != nil && r.OTP == nil && r.Continuation == nil && r.Session.Authentication.Kind == AuthenticationVerified) ||
		(r.Schema == 3 && r.CSRF == nil && r.OTP != nil && r.Continuation == nil && r.Session.Authentication.Kind == AuthenticationOTP) ||
		(r.Schema == 4 && r.CSRF != nil && r.OTP != nil && r.Continuation == nil && r.Session.Authentication.Kind == AuthenticationOTP) ||
		(r.Schema == 5 && r.CSRF == nil && r.OTP == nil && r.Continuation != nil && r.Session.Authentication.Kind == AuthenticationVerified) ||
		(r.Schema == 6 && r.CSRF != nil && r.OTP == nil && r.Continuation != nil && r.Session.Authentication.Kind == AuthenticationVerified)) ||
		(r.Schema == 7 && r.CSRF == nil && r.OTP == nil && r.Continuation == nil && r.MagicLink != nil && r.Session.Authentication.Kind == AuthenticationMagicLink) ||
		(r.Schema == 8 && r.CSRF != nil && r.OTP == nil && r.Continuation == nil && r.MagicLink != nil && r.Session.Authentication.Kind == AuthenticationMagicLink)) ||
		(r.Schema == 9 && r.CSRF == nil && r.OTP == nil && r.Continuation == nil && r.MagicLink != nil && r.MFA != nil && r.Session.Authentication.Kind == AuthenticationMagicLink) ||
		(r.Schema == 10 && r.CSRF != nil && r.OTP == nil && r.Continuation == nil && r.MagicLink != nil && r.MFA != nil && r.Session.Authentication.Kind == AuthenticationMagicLink) ||
		(r.Schema == 11 && r.CSRF == nil && r.OTP == nil && r.Continuation == nil && r.MagicLink == nil && r.MFA != nil && r.Session.Authentication.Kind == AuthenticationVerified) ||
		(r.Schema == 12 && r.CSRF != nil && r.OTP == nil && r.Continuation == nil && r.MagicLink == nil && r.MFA != nil && r.Session.Authentication.Kind == AuthenticationVerified)
	if !bytes.Equal(plaintext, canonical) || !validSchema || (c.service.method != 0 && r.Session.Authentication.Kind != c.service.method) || r.Session.TenantID != tenant || r.Session.Audience != c.service.config.Audience || (r.Transport != CredentialCookie && r.Transport != CredentialBearer) || !validTime(r.AcceptedAt) || !validTime(r.Until) || !validTime(r.StoredAt) || r.StoredAt.Before(r.AcceptedAt) || !r.Until.After(r.StoredAt) || r.Until.After(r.AcceptedAt.Add(20*time.Second)) {
		return CachedAdmission{}
	}
	remember, e := NewRememberPolicy(r.Session.Remember)
	if e != nil {
		return CachedAdmission{}
	}
	authority, e := NewAuthoritySnapshot(r.Session.Authority)
	if e != nil {
		return CachedAdmission{}
	}
	s := r.Session
	var metadata OTPAuthentication
	if r.OTP != nil {
		metadata, e = NewOTPAuthentication(*r.OTP)
		if e != nil {
			return CachedAdmission{}
		}
	}
	var magicLink MagicLinkAuthentication
	if r.MagicLink != nil {
		magicLink, e = NewMagicLinkAuthentication(*r.MagicLink)
		if e != nil {
			return CachedAdmission{}
		}
	}
	var mfa MFAAuthentication
	if r.MFA != nil {
		mfa, e = NewMFAAuthentication(*r.MFA)
		if e != nil {
			return CachedAdmission{}
		}
	}
	record, e := newSessionWithMFA(SessionSpec{s.SessionID, s.FamilyID, s.TenantID, s.UserID, s.Audience, s.Version, s.FamilyVersion, remember, authority, s.Lookup, s.Authentication, s.IssuedAt, s.LastActivityAt}, metadata, magicLink, mfa)
	if e != nil || !r.Eligible.Equal(s.LastActivityAt.Add(remember.refresh)) {
		return CachedAdmission{}
	}
	if r.Continuation != nil {
		spec, _ := record.Bindings()
		record, e = NewContinuedPasswordSession(spec, CSRFState{}, *r.Continuation)
		if e != nil {
			return CachedAdmission{}
		}
	}
	if r.CSRF != nil {
		state, e := NewCSRFState(*r.CSRF)
		if e != nil {
			return CachedAdmission{}
		}
		record, e = attachCSRF(record, state)
		if e != nil {
			return CachedAdmission{}
		}
	}
	if cap := r.StoredAt.Add(c.config.MaximumAge); cap.Before(r.Until) {
		r.Until = cap
	}
	result := GetResult{Authenticated: true, Session: record, NeedsRefresh: r.NeedsRefresh, RefreshEligibleAt: r.Eligible, validity: &sessionAdmission{owner: c.service, transport: r.Transport, session: record, refresh: r.NeedsRefresh, eligible: r.Eligible, acceptedAt: r.AcceptedAt, until: r.Until}}
	return CachedAdmission{&cachedAdmissionState{result}}
}

func (c *EncryptedCacheCodec) additionalData(tenant identity.TenantID) (envelope.Context, error) {
	fields := map[string]string{"purpose": "golib.session.encrypted-cache.v1", "issuer": c.config.Issuer, "environment": c.config.Environment, "epoch": strconv.FormatUint(c.config.DeploymentEpoch, 10), "audience": c.service.config.Audience, "tenant": string(tenant), "clock-uncertainty": strconv.FormatInt(int64(c.service.config.ClockUncertainty), 10)}
	// Closed native methods must not share positive authority through a warm
	// cache, even when wrapping and lookup keys are shared. Legacy generic
	// reader-selected composition keeps its original framing; a closed reader
	// cannot restore that unbound framing and must refresh from primary.
	if c.service.method != 0 {
		fields["authentication-kind"] = strconv.FormatUint(uint64(c.service.method), 10)
	}
	if c.service.methods != 0 {
		fields["authentication-selection"] = strconv.FormatUint(uint64(c.service.methods), 10)
	}
	if c.service.cacheProfile != "" {
		fields["admission-profile"] = c.service.cacheProfile
	}
	return envelope.NewContext(fields)
}
func cacheCryptoError(ctx context.Context, e error) error {
	if ctx.Err() != nil {
		return sessionReadFailure(ctx)
	}
	if errors.Is(e, context.Canceled) {
		return identity.CancelledError{}
	}
	if errors.Is(e, context.DeadlineExceeded) {
		return identity.DeadlineExceededError{}
	}
	return ErrUnavailable
}

// Format prevents key/profile identifiers from leaking through diagnostics.
func (*EncryptedCacheCodec) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.EncryptedCacheCodec(redacted)"))
}

// MarshalJSON denies implicit profile/key-reference export.
func (*EncryptedCacheCodec) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }
