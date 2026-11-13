package sessionvalkey

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// Checkpoint is opaque cache-generation custody captured before authoritative
// admission. Zero, a foreign cache and altered request cannot fill. Copies may
// retry only while the original admission and captured generation remain valid.
// A checkpoint is not authentication and must not be logged or serialized.
type Checkpoint struct{ state *checkpointState }
type checkpointState struct {
	owner                  *Cache
	request                session.GetRequest
	digests                []session.TokenDigest
	keys                   []string
	marker, epoch, barrier string
	at                     time.Time
}

// Format redacts stable lookup and scope metadata.
func (Checkpoint) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[REDACTED]") }

// MarshalJSON prevents persisting a live checkpoint as a credential substitute.
func (Checkpoint) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }

// MarshalText prevents persisting a live checkpoint as a credential substitute.
func (Checkpoint) MarshalText() ([]byte, error) { return nil, ErrInvalidInput }

// Get uses only authenticated original-deadline ciphertext or the codec's
// existing primary fallback. Cache errors/misses never become allow/deny claims.
// All positive results must still be ValidateAt-checked before application use.
// Filling is best-effort and cannot alter the original result or renew validity.
func (c *Cache) Get(ctx context.Context, request session.GetRequest) (session.GetResult, error) {
	bounded, done, err := c.begin(ctx)
	if err != nil {
		return session.GetResult{}, err
	}
	defer done()
	checkpoint, blob, _ := c.checkpoint(bounded, request)
	result, err := c.codec.Get(bounded, request, blob)
	if err != nil {
		return session.GetResult{}, err
	}
	if !result.Authenticated {
		return result, nil
	}
	now := c.now()
	if now.IsZero() {
		return session.GetResult{}, ErrUnavailable
	}
	if result.ValidateAt(now) != nil {
		return session.GetResult{}, session.ErrUnauthenticated
	}
	if checkpoint.state != nil {
		_, _ = c.fill(bounded, checkpoint, result)
	}
	if bounded.Err() != nil {
		return session.GetResult{}, ErrUnavailable
	}
	finished := c.now()
	if finished.IsZero() || finished.Before(now) {
		return session.GetResult{}, ErrUnavailable
	}
	if result.ValidateAt(finished) != nil {
		return session.GetResult{}, session.ErrUnauthenticated
	}
	return result, nil
}

// Checkpoint captures generations before a separately performed primary read.
// Cache outage returns ErrUnavailable; applications should use primary without
// filling, never pretend a checkpoint was captured. It owns no primary read.
func (c *Cache) Checkpoint(ctx context.Context, request session.GetRequest) (Checkpoint, error) {
	bounded, done, err := c.begin(ctx)
	if err != nil {
		return Checkpoint{}, err
	}
	defer done()
	checkpoint, _, err := c.checkpoint(bounded, request)
	return checkpoint, err
}

func (c *Cache) checkpoint(ctx context.Context, request session.GetRequest) (Checkpoint, []byte, error) {
	if !ascii(string(request.TenantID), 128) {
		return Checkpoint{}, nil, ErrInvalidInput
	}
	now := c.now()
	if now.IsZero() {
		return Checkpoint{}, nil, ErrUnavailable
	}
	p := &checkpointState{owner: c, request: request, at: now, marker: c.marker(request.TenantID)}
	for _, key := range c.config.LookupKeys {
		digest, err := request.Credential.Digest(key, string(request.TenantID))
		if err != nil {
			return Checkpoint{}, nil, ErrInvalidInput
		}
		p.digests = append(p.digests, digest)
		p.keys = append(p.keys, c.entry(request, digest))
	}
	values, err := c.run(ctx, "read", p.marker, p.keys, nil)
	if err != nil {
		return Checkpoint{}, nil, err
	}
	if c.now().Before(now) {
		return Checkpoint{}, nil, ErrUnavailable
	}
	p.epoch, p.barrier = values[0], values[1]
	return Checkpoint{p}, []byte(values[2]), nil
}

// Fill seals only unchanged same-codec primary/cached admission and atomically
// rejects any exact/family invalidation since Checkpoint. False,nil means a
// generation changed. No raw bearer/plaintext is stored. The physical TTL is
// rounded down from the original exclusive deadline, never a refreshed lease.
func (c *Cache) Fill(ctx context.Context, checkpoint Checkpoint, result session.GetResult) (bool, error) {
	if c == nil || checkpoint.state == nil || checkpoint.state.owner != c {
		return false, ErrInvalidInput
	}
	bounded, done, err := c.begin(ctx)
	if err != nil {
		return false, err
	}
	defer done()
	return c.fill(bounded, checkpoint, result)
}

func (c *Cache) fill(ctx context.Context, checkpoint Checkpoint, result session.GetResult) (bool, error) {
	p := checkpoint.state
	if p == nil || p.owner != c {
		return false, ErrInvalidInput
	}
	now := c.now()
	if now.IsZero() {
		return false, ErrUnavailable
	}
	if now.Before(p.at) || result.ValidateAt(now) != nil {
		return false, ErrInvalidInput
	}
	spec, err := result.Session.Bindings()
	if err != nil || spec.TenantID != p.request.TenantID {
		return false, ErrInvalidInput
	}
	entry := ""
	for i, digest := range p.digests {
		if digest == spec.Lookup {
			entry = p.keys[i]
		}
	}
	if entry == "" {
		return false, ErrInvalidInput
	}
	blob, err := c.codec.Seal(ctx, result)
	if err != nil {
		return false, unavailable("seal", err)
	}
	defer clear(blob)
	if len(blob) > c.config.MaximumPayloadBytes {
		return false, ErrInvalidInput
	}
	now = c.now()
	if now.IsZero() {
		return false, unavailable("fill-clock", nil)
	}
	if now.Before(p.at) || result.ValidateAt(now) != nil {
		return false, ErrInvalidInput
	}
	ttl, ok := milliseconds(result.ValidUntil().Sub(now))
	if !ok {
		return false, ErrInvalidInput
	}
	values, err := c.run(ctx, "fill", p.marker, []string{entry}, []string{p.epoch, p.barrier, c.scope(spec.TenantID, "s", spec.SessionID), c.scope(spec.TenantID, "f", spec.FamilyID), string(blob), ttl, strconv.FormatInt(result.ValidUntil().UnixMilli(), 10)})
	if err != nil {
		return false, err
	}
	finished := c.now()
	if finished.Before(now) || result.ValidateAt(finished) != nil {
		return false, unavailable("fill-post-validation", nil)
	}
	return values[0] == p.epoch && values[1] == p.barrier, nil
}

// Invalidate fences exact-session entries and any in-flight tenant fills. Call
// after primary revocation; success is cache invalidation, not durable revocation.
// Unknown transport outcomes return ErrUnavailable, never rollback or authority.
func (c *Cache) Invalidate(ctx context.Context, tenant identity.TenantID, sessionID string) error {
	return c.invalidate(ctx, tenant, "s", sessionID)
}

// InvalidateFamily fences all entries in an exact tenant/family without an
// unbounded membership index. Unrelated existing entries remain usable unless
// bounded generation capacity requires a conservative epoch reset.
func (c *Cache) InvalidateFamily(ctx context.Context, tenant identity.TenantID, familyID string) error {
	return c.invalidate(ctx, tenant, "f", familyID)
}

func (c *Cache) invalidate(ctx context.Context, tenant identity.TenantID, kind, id string) error {
	if !ascii(string(tenant), 128) || !ascii(id, 128) {
		return ErrInvalidInput
	}
	bounded, done, err := c.begin(ctx)
	if err != nil {
		return err
	}
	defer done()
	_, err = c.run(bounded, "invalidate", c.marker(tenant), nil, []string{c.scope(tenant, kind, id)})
	return cleanError(err)
}

func (c *Cache) hash(parts ...string) string {
	h := hmac.New(sha256.New, []byte(c.config.NamespaceKey.state.value))
	for _, p := range parts {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(p)))
		_, _ = h.Write(size[:])
		_, _ = io.WriteString(h, p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (c *Cache) marker(tenant identity.TenantID) string {
	return "session-positive-v1:" + c.hash("namespace", c.config.Namespace, strconv.FormatUint(c.config.DeploymentEpoch, 10), string(tenant))
}

func (c *Cache) scope(tenant identity.TenantID, kind, id string) string {
	return kind + ":" + c.hash("scope", c.config.Namespace, strconv.FormatUint(c.config.DeploymentEpoch, 10), string(tenant), kind, id)
}

func (c *Cache) entry(request session.GetRequest, digest session.TokenDigest) string {
	return c.marker(request.TenantID) + ":" + c.hash("entry", strconv.Itoa(int(request.Credential.Kind())), strconv.FormatUint(uint64(digest.KeyVersion), 10), string(digest.Sum[:]))
}
