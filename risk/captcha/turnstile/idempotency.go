package turnstile

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"

	"github.com/faustbrian/go-identity/risk/captcha"
)

// Cloudflare Siteverify accepts UUID transport idempotency. RFC 9562 section
// 5.8 permits a SHA-256-based version-8 layout. This domain-separated transport
// projection is scoped to the issuer's original command and trusted flow,
// immutable provider profile/site/config and token digest. Full flow binding
// prevents a provider retry from crossing tenant, actor or challenge custody;
// it is never exposed as replay authority.
// The risk issuer still authenticates exact Flow/token custody and owns replay.
func idempotency(r captcha.VerifyRequest, p captcha.Config) string {
	h := sha256.New()
	_, _ = h.Write([]byte("golib-turnstile-transport-idempotency-v1\x00"))
	var width [4]byte
	fields := []string{r.CommandID, p.Provider, p.SiteKey, p.APIProfile, p.API, p.Version, p.Tier, p.ConfigurationVersion, p.ExpectedAction, strconv.FormatBool(p.ExpectedCData.Available), p.ExpectedCData.Value}
	// The neutral verifier rejects zero flow before this callback. Bindings is
	// trusted metadata, not an authorization assertion or token replay digest.
	flow, _ := r.Flow.Bindings()
	fields = append(fields, string(flow.Kind), flow.Tenant, string(flow.Operation), flow.Subject, flow.AnonymousFlow, flow.PreAuthTransaction, flow.Session, flow.Actor, flow.ChallengeID, flow.RequestFingerprint)
	fields = append(fields, p.Hostnames...)
	for _, value := range fields {
		binary.BigEndian.PutUint32(width[:], uint32(len(value)))
		_, _ = h.Write(width[:])
		_, _ = h.Write([]byte(value))
	}
	token := sha256.Sum256(r.Token)
	defer clear(token[:])
	_, _ = h.Write(token[:])
	sum := h.Sum(nil)
	defer clear(sum)
	var id [16]byte
	copy(id[:], sum)
	defer clear(id[:])
	id[6] = (id[6] & 0x0f) | 0x80
	id[8] = (id[8] & 0x3f) | 0x80
	var text [36]byte
	hex.Encode(text[:8], id[:4])
	text[8] = '-'
	hex.Encode(text[9:13], id[4:6])
	text[13] = '-'
	hex.Encode(text[14:18], id[6:8])
	text[18] = '-'
	hex.Encode(text[19:23], id[8:10])
	text[23] = '-'
	hex.Encode(text[24:], id[10:])
	return string(text[:])
}
