package apikey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// ProjectionAuthorityReader supplies a genuine bounded primary observation of
// an already authenticated USER key. It cannot authenticate a candidate, debit
// quota or replace AtomicVerifier. Implementations must preserve original times.
type ProjectionAuthorityReader interface {
	ObserveSourceAuthority(context.Context, SourceAuthorityBinding) (SourceAuthorityObservation, error)
}

// ProjectionClock is the trusted, fast concurrency-safe clock for projection
// eligibility only. It must account for the source profile's clock uncertainty.
type ProjectionClock interface{ Now() time.Time }

// PositiveProjectionConfig separately opts into encrypted modern USER metadata.
// It does not change Configuration.Cache or any native verification profile.
// Store, Verifier and Authority must be the actual public source owners (one
// object may implement all three); they and Crypto/Clock remain borrowed.
// Every Begin invokes Verifier exactly once. There is no source-free, cached
// authentication, quota allowance, legacy or organization variant.
//
// Namespace and positive DeploymentEpoch isolate deployments; KeyReference is
// the envelope provider's wrapping key, not an API-key pepper. MaximumDuration
// is 1ms..5s and MaximumBytes is 1024..262144. All transport calls must also fit
// their caller's bounded overall context. No background work is started.
type PositiveProjectionConfig struct {
	Configuration   Configuration
	TenantID        identity.TenantID
	Store           Store
	Verifier        AtomicVerifier
	Authority       ProjectionAuthorityReader
	Crypto          *envelope.Service
	Clock           ProjectionClock
	Namespace       string
	DeploymentEpoch uint64
	KeyReference    string
	MaximumDuration time.Duration
	MaximumBytes    int
}

func (PositiveProjectionConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "apikey.PositiveProjectionConfig(redacted)")
}
func (PositiveProjectionConfig) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }

// PositiveProjectionCodec binds projection production/consumption to its actual
// injected source invocation, never a caller-constructed VerificationResult.
// Concurrent use requires concurrent-safe borrowed sources/crypto/clock. It owns
// no journal, transaction, authority vector, cache connection or worker.
type PositiveProjectionCodec struct {
	config PositiveProjectionConfig
	frame  string
}

// NewPositiveProjectionCodec validates explicit composition without IO. Existing
// source CacheDisabled configuration and old serialized identities stay intact.
func NewPositiveProjectionCodec(c PositiveProjectionConfig) (*PositiveProjectionCodec, error) {
	profile := c.Configuration.Spec()
	if c.Configuration.Validate() != nil || profile.Algorithm != AlgorithmModernHMACSHA256 || profile.State != ConfigurationActive || profile.Cache != CacheDisabled || !scope(string(c.TenantID), 128) || projectionNil(c.Store) || projectionNil(c.Verifier) || projectionNil(c.Authority) || c.Crypto == nil || projectionNil(c.Clock) || !scope(c.Namespace, 128) || c.DeploymentEpoch == 0 || !scope(c.KeyReference, 256) || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 5*time.Second || c.MaximumBytes < 1024 || c.MaximumBytes > 262144 {
		return nil, ErrInvalid
	}
	wire, err := json.Marshal(profile)
	if err != nil {
		return nil, ErrInvalid
	}
	frame := sha256.Sum256(wire)
	return &PositiveProjectionCodec{config: c, frame: hex.EncodeToString(frame[:])}, nil
}

func projectionNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// PositiveProjectionLookup is nonsecret scope/epoch metadata, not a digest or
// credential. It is usable only as cache addressing after a genuine source
// verification. Transports must namespace/hash it; never log stable identifiers.
type PositiveProjectionLookup struct {
	TenantID                          identity.TenantID
	ConfigurationID                   string
	ConfigurationRevision             uint64
	KeyID                             KeyID
	KeyAuthorityVersion               uint64
	OwnerID                           identity.UserID
	OwnerVersion                      uint64
	ConfigurationAuthorityVersion     uint64
	GlobalVersion, TenantVersion      uint64
	UserVersion, AuthorizationVersion uint64
	PolicyVersion                     uint64
}

func (PositiveProjectionLookup) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "apikey.PositiveProjectionLookup(redacted)")
}
func (PositiveProjectionLookup) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }

// PositiveProjectionAdmission is opaque same-codec custody from one completed
// source invocation. It contains no request credential/digest. Copies preserve
// the original result/window and cannot select a new verification attempt.
type PositiveProjectionAdmission struct{ state *positiveProjectionAdmission }
type positiveProjectionAdmission struct {
	owner    *PositiveProjectionCodec
	result   AtomicVerificationResult
	lookup   PositiveProjectionLookup
	grant    []string
	required []string
	start    time.Time
	until    time.Time
}

func (PositiveProjectionAdmission) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "apikey.PositiveProjectionAdmission(redacted)")
}
func (PositiveProjectionAdmission) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }

// Cacheable reports projection eligibility, never permission or authentication.
func (a PositiveProjectionAdmission) Cacheable() bool { return a.state != nil }

// Lookup returns metadata only from this genuine source invocation. Zero denies.
func (a PositiveProjectionAdmission) Lookup() (PositiveProjectionLookup, error) {
	if a.state == nil {
		return PositiveProjectionLookup{}, ErrInvalid
	}
	return a.state.lookup, nil
}

// Begin invokes the configured AtomicVerifier exactly once with the original
// attempt. Ambiguity/denial/error and known quota metadata pass through unchanged
// and cannot publish a positive. Additional authority/crypto/cache failure never
// retries verification or hides its known outcome. Unsupported request profiles
// fail before source work. Only modern USER positives can receive admission.
func (c *PositiveProjectionCodec) Begin(ctx context.Context, request AtomicVerificationRequest) (admission PositiveProjectionAdmission, out AtomicVerificationResult, err error) {
	if c == nil || ctx == nil || request.TenantID != c.config.TenantID || request.Validate(c.config.Configuration) != nil {
		return admission, out, ErrInvalid
	}
	ctx, stop := context.WithTimeout(ctx, c.config.MaximumDuration)
	defer stop()
	out, err = c.config.Verifier.VerifyAndConsume(ctx, request)
	defer func() {
		if recover() != nil {
			// The verifier has already returned its actual receipt/quota. A
			// later authority/clock panic cannot turn that known debit into
			// PossibleDebit or erase original recovery. Deny the principal only.
			admission = PositiveProjectionAdmission{}
			out.Result = nil
			err = identity.UnavailableError{}
		}
	}()
	if err != nil {
		return admission, out, err
	}
	if out.Validate() != nil || out.AttemptID != request.AttemptID {
		out.Result = nil
		return admission, out, ErrInvalid
	}
	if out.Result == nil {
		return admission, out, nil
	}
	if out.State != VerificationAttemptNotApplicable && out.State != VerificationAttemptDebited || out.Result.Owner.Spec().Kind != OwnerUser {
		out.Result = nil
		return admission, out, ErrDenied
	}
	// Native verification time can use the primary clock. Structural validation
	// uses that original instant; projection use separately requires this clock
	// inside the original window, without retiming either source observation.
	result := *out.Result
	if result.ValidateAt(c.config.Configuration, result.VerifiedAt) != nil || result.Owner.Spec().TenantID != request.TenantID {
		out.Result = nil
		return admission, out, ErrInvalid
	}
	binding, e := NewSourceAuthorityBinding(result, c.config.Configuration, result.VerifiedAt)
	if e != nil {
		out.Result = nil
		return admission, out, ErrDenied
	}
	observed, e := c.config.Authority.ObserveSourceAuthority(ctx, binding)
	if e != nil || observed.Validate(binding, c.config.Configuration, observed.VerifiedAt) != nil {
		// This is a primary authority read, not an optional cache operation.
		// A known debit remains historical metadata; it cannot retain a principal
		// when the contributing current authority cannot be established.
		out.Result = nil
		return admission, out, ErrDenied
	}
	start, until := result.ReadStartedAt, minProjectionTime(result.ValidUntil, observed.ValidUntil)
	if observed.ReadStartedAt.Before(start) {
		start = observed.ReadStartedAt
	}
	now := c.config.Clock.Now()
	if ctx.Err() != nil || now.Before(start) || !now.Before(until) {
		out.Result = nil
		return admission, out, ErrDenied
	}
	owner := observed.Owner.Spec()
	lookup := PositiveProjectionLookup{TenantID: owner.TenantID, ConfigurationID: result.Record.ConfigurationID, ConfigurationRevision: result.Record.ConfigurationRevision, KeyID: result.Record.ID, KeyAuthorityVersion: result.Record.AuthorityVersion, OwnerID: owner.UserID, OwnerVersion: owner.Version, ConfigurationAuthorityVersion: observed.ConfigurationAuthority.Version, GlobalVersion: observed.GlobalVersion, TenantVersion: observed.TenantVersion, UserVersion: observed.UserVersion, AuthorizationVersion: observed.AuthorizationVersion, PolicyVersion: observed.PolicyVersion}
	admission.state = &positiveProjectionAdmission{owner: c, result: cloneProjectionResult(out), lookup: lookup, grant: projectionIntersection(result.Grant, observed.Grant), required: slices.Clone(request.RequiredPermissions), start: start, until: until}
	return admission, out, err
}

// PositiveProjectionPublication is authenticated ciphertext for trusted cache
// persistence, never a bearer. Its physical TTL must be rounded DOWN from the
// original ValidUntil. Zero publishes nothing; failure is best-effort only.
type PositiveProjectionPublication struct {
	Ciphertext    []byte
	ReadStartedAt time.Time
	ValidUntil    time.Time
}

func (PositiveProjectionPublication) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "apikey.PositiveProjectionPublication(redacted)")
}
func (PositiveProjectionPublication) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }

// Complete can only narrow the CURRENT source result. It never returns a cached
// attempt/fingerprint/quota as a new result. Native read/verified timestamps stay
// native; only grant and deadline may narrow. An eligible cached projection's
// own original start/deadline survive publication unchanged, including promotion.
// Missing/corrupt/foreign/stale blobs use the already-obtained source result,
// not a second source call. Cache/envelope failures cannot hide a known outcome.
func (c *PositiveProjectionCodec) Complete(ctx context.Context, admission PositiveProjectionAdmission, blob []byte) (out AtomicVerificationResult, publication PositiveProjectionPublication, err error) {
	a := admission.state
	if c == nil || ctx == nil || a == nil || a.owner != c {
		return AtomicVerificationResult{}, PositiveProjectionPublication{}, ErrInvalid
	}
	out = cloneProjectionResult(a.result)
	ctx, stop := context.WithTimeout(ctx, c.config.MaximumDuration)
	defer stop()
	start, until, grant := a.start, a.until, slices.Clone(a.grant)
	defer func() {
		// Crypto/cache failure is optional, elapsed primary authority is not.
		// Check every return after potentially blocking envelope work, including
		// error paths, without changing the known native debit or original scope.
		if out.Result != nil {
			now := c.config.Clock.Now()
			if now.Before(start) || !now.Before(until) {
				out.Result = nil
				publication = PositiveProjectionPublication{}
				err = ErrDenied
			}
		}
	}()
	if cached, ok := c.restore(ctx, a.lookup, blob); ok {
		narrowed := projectionIntersection(grant, cached.Grant)
		// A projection cannot turn a current positive into an ambiguous/negative
		// debit result. A different permission requirement is a projection miss;
		// the native owner has already decided that actual request exactly once.
		if projectionSubset(a.required, narrowed) && cached.ValidUntil.After(out.Result.VerifiedAt) {
			grant = narrowed
			start = minProjectionTime(start, cached.ReadStartedAt)
			until = minProjectionTime(until, cached.ValidUntil)
		}
	}
	now := c.config.Clock.Now()
	if now.Before(start) || !now.Before(until) || !projectionSubset(a.required, grant) || !until.After(out.Result.VerifiedAt) {
		// Unlike optional ciphertext/transport failure, this is an obtained
		// authoritative denial/expiry. Preserve original committed debit/history
		// without a principal, never relabel it NotDebited or issue success.
		out.Result = nil
		return out, PositiveProjectionPublication{}, ErrDenied
	}
	out.Result.Grant = slices.Clone(grant)
	out.Result.ValidUntil = minProjectionTime(out.Result.ValidUntil, until)
	if ctx.Err() != nil {
		return out, PositiveProjectionPublication{}, nil
	}
	stored := positiveProjectionRecord{Schema: 1, Lookup: projectionLookupRecord(a.lookup), Grant: grant, ReadStartedAt: start, ValidUntil: until, AttemptID: out.AttemptID, State: out.State, Quota: out.Quota}
	plain, e := json.Marshal(stored)
	defer clear(plain)
	if e != nil || len(plain) > c.config.MaximumBytes {
		return out, PositiveProjectionPublication{}, nil
	}
	aad, e := c.additionalData(a.lookup)
	if e != nil {
		return out, PositiveProjectionPublication{}, nil
	}
	sealed, e := c.config.Crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: c.config.KeyReference, Context: aad})
	if e != nil || ctx.Err() != nil {
		return out, PositiveProjectionPublication{}, nil
	}
	wire, e := sealed.MarshalBinary()
	if e != nil || len(wire) > c.config.MaximumBytes {
		return out, PositiveProjectionPublication{}, nil
	}
	return out, PositiveProjectionPublication{Ciphertext: wire, ReadStartedAt: start, ValidUntil: until}, nil
}

// Reconcile delegates exact original status inquiry only, never verification,
// projection promotion, permission maintenance, refill or debit.
func (c *PositiveProjectionCodec) Reconcile(ctx context.Context, q VerificationReconcileQuery) (AtomicVerificationResult, error) {
	if c == nil || ctx == nil || q.TenantID != c.config.TenantID || q.Validate() != nil {
		return AtomicVerificationResult{}, ErrInvalid
	}
	ctx, stop := context.WithTimeout(ctx, c.config.MaximumDuration)
	defer stop()
	return c.config.Verifier.ReconcileVerifyAndConsume(ctx, q)
}

type projectionLookupRecord PositiveProjectionLookup
type positiveProjectionRecord struct {
	Schema                    uint16
	Lookup                    projectionLookupRecord
	Grant                     []string
	ReadStartedAt, ValidUntil time.Time
	AttemptID                 VerificationAttemptID
	State                     VerificationAttemptState
	Quota                     *QuotaMetadata `json:",omitempty"`
}

func (c *PositiveProjectionCodec) additionalData(lookup PositiveProjectionLookup) (envelope.Context, error) {
	wire, err := json.Marshal(projectionLookupRecord(lookup))
	if err != nil {
		return envelope.Context{}, ErrInvalid
	}
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{"purpose": "apikey.modern-user-positive-metadata.v1", "namespace": c.config.Namespace, "deployment": strconv.FormatUint(c.config.DeploymentEpoch, 10), "configuration": c.frame, "binding": hex.EncodeToString(digest[:])})
}

func (c *PositiveProjectionCodec) restore(ctx context.Context, lookup PositiveProjectionLookup, blob []byte) (positiveProjectionRecord, bool) {
	if len(blob) == 0 || len(blob) > c.config.MaximumBytes {
		return positiveProjectionRecord{}, false
	}
	sealed, err := envelope.ParseEnvelope(blob)
	if err != nil {
		return positiveProjectionRecord{}, false
	}
	aad, err := c.additionalData(lookup)
	if err != nil {
		return positiveProjectionRecord{}, false
	}
	plain, err := c.config.Crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) > c.config.MaximumBytes {
		return positiveProjectionRecord{}, false
	}
	var stored positiveProjectionRecord
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&stored) != nil {
		return positiveProjectionRecord{}, false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || stored.Schema != 1 || PositiveProjectionLookup(stored.Lookup) != lookup || !validPermissions(stored.Grant) || stored.ReadStartedAt.IsZero() || !stored.ValidUntil.After(stored.ReadStartedAt) || stored.ValidUntil.Sub(stored.ReadStartedAt) > 20*time.Second || c.config.Clock.Now().Before(stored.ReadStartedAt) || !c.config.Clock.Now().Before(stored.ValidUntil) {
		return positiveProjectionRecord{}, false
	}
	if _, err := ParseVerificationAttemptID(string(stored.AttemptID)); err != nil || stored.State != VerificationAttemptNotApplicable && stored.State != VerificationAttemptDebited || stored.State == VerificationAttemptDebited && stored.Quota == nil || stored.Quota != nil && stored.Quota.Validate() != nil {
		return positiveProjectionRecord{}, false
	}
	return stored, true
}

func cloneProjectionResult(out AtomicVerificationResult) AtomicVerificationResult {
	if out.Result != nil {
		copy := *out.Result
		copy.Grant, copy.Record.Grant = slices.Clone(copy.Grant), slices.Clone(copy.Record.Grant)
		out.Result = &copy
	}
	if out.Quota != nil {
		copy := *out.Quota
		out.Quota = &copy
	}
	return out
}
func projectionIntersection(current, ceiling []string) []string {
	out := make([]string, 0, len(current))
	for _, permission := range current {
		if slices.Contains(ceiling, permission) {
			out = append(out, permission)
		}
	}
	return out
}
func projectionSubset(required, grant []string) bool {
	for _, permission := range required {
		if !slices.Contains(grant, permission) {
			return false
		}
	}
	return true
}
func minProjectionTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
