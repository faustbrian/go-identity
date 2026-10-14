package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-identity/delivery"
)

// The owned v1 callback profile is not a vendor signature approximation. Keys
// select exactly one deployment/tenant/provider/version/actor. Retained keys
// permit rotation only during explicit validity intervals; a retired key cannot
// authorize even an already recorded event. This is authentication, not policy
// admission, durable deduplication or authority to disclose an original result.
type receiptAuthProfile struct {
	Tenant, Provider, Actor, KeyID string
	Version                        uint64
	Key                            [32]byte
	NotBefore, NotAfter            time.Time
}

type receiptSignedInput struct {
	Tenant, Provider, KeyID string
	Version                 uint64
	SignedAt                time.Time
	Body                    []byte
	Signature               [32]byte
}

type receiptAuthenticator struct {
	deployment string
	profiles   []receiptAuthProfile
	maxBytes   int
}

func newReceiptAuthenticator(deployment string, profiles []receiptAuthProfile, maxBytes int) (*receiptAuthenticator, error) {
	if !safeID(deployment, false) || len(profiles) == 0 || len(profiles) > 32 || maxBytes < 256 || maxBytes > 65536 {
		return nil, delivery.ErrInvalidInput
	}
	for i, p := range profiles {
		sample := delivery.ReceiptRecordRequest{TenantID: delivery.TenantID(p.Tenant), IntentID: "profile-validation", Provider: p.Provider, ProviderEventID: "profile-validation", Generation: 1, Status: delivery.StateAccepted, ObservedAt: p.NotBefore, IdempotencyKey: "profile-validation"}
		if sample.Validate() != nil || !safeID(p.Tenant, false) || !safeID(p.Actor, false) || !safeID(p.KeyID, false) || p.Version == 0 || p.Key == ([32]byte{}) || !receiptUTCTime(p.NotBefore) || !receiptUTCTime(p.NotAfter) || !p.NotBefore.Before(p.NotAfter) {
			return nil, delivery.ErrInvalidInput
		}
		for _, prior := range profiles[:i] {
			if prior.Tenant == p.Tenant && prior.Provider == p.Provider && prior.Version == p.Version && prior.KeyID == p.KeyID {
				return nil, delivery.ErrInvalidInput
			}
		}
	}
	return &receiptAuthenticator{deployment: deployment, profiles: append([]receiptAuthProfile(nil), profiles...), maxBytes: maxBytes}, nil
}

func receiptUTCTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1 && t.Year() <= 9999
}

// now is the owning service's current trusted clock observation, never callback
// input. Freshness belongs to the signed envelope, not the possibly delayed
// provider observation. Both current time and signing time must fit key custody.
// Callers retain ownership of input bytes and must not mutate them concurrently.
func (a *receiptAuthenticator) verify(ctx context.Context, input receiptSignedInput, now time.Time) (delivery.ReceiptRecordRequest, string, error) {
	if a == nil || ctx == nil || !receiptUTCTime(now) {
		return delivery.ReceiptRecordRequest{}, "", delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return delivery.ReceiptRecordRequest{}, "", err
	}
	if len(input.Body) == 0 || len(input.Body) > a.maxBytes || !safeID(input.Tenant, false) || !safeID(input.Provider, false) || !safeID(input.KeyID, false) || input.Version == 0 || !receiptUTCTime(input.SignedAt) {
		return delivery.ReceiptRecordRequest{}, "", delivery.ErrInvalidInput
	}
	var selected *receiptAuthProfile
	for i := range a.profiles {
		p := &a.profiles[i]
		if p.Tenant == input.Tenant && p.Provider == input.Provider && p.Version == input.Version && p.KeyID == input.KeyID {
			selected = p
			break
		}
	}
	if selected == nil || now.Before(selected.NotBefore) || !now.Before(selected.NotAfter) || input.SignedAt.Before(selected.NotBefore) || !input.SignedAt.Before(selected.NotAfter) || !now.Before(input.SignedAt.Add(5*time.Minute)) || input.SignedAt.After(now.Add(30*time.Second)) {
		return delivery.ReceiptRecordRequest{}, "", delivery.ErrForbidden
	}
	scope, _ := json.Marshal([]string{a.deployment, input.Tenant, input.Provider, strconv.FormatUint(input.Version, 10), input.KeyID, input.SignedAt.Format(time.RFC3339Nano)})
	expected := custodyMAC(selected.Key, "identity-delivery-receipt-hmac-sha256-v1", scope, input.Body)
	clear(scope)
	if !hmac.Equal(expected[:], input.Signature[:]) {
		return delivery.ReceiptRecordRequest{}, "", delivery.ErrForbidden
	}
	q, err := parseReceiptCallback(input.Body)
	if err != nil {
		return delivery.ReceiptRecordRequest{}, "", err
	}
	if string(q.TenantID) != selected.Tenant || q.Provider != selected.Provider {
		return delivery.ReceiptRecordRequest{}, "", delivery.ErrForbidden
	}
	if err := ctx.Err(); err != nil {
		return delivery.ReceiptRecordRequest{}, "", err
	}
	return q, selected.Actor, nil
}

// Decode exact field names once each; encoding/json alone silently accepts
// duplicates and case-insensitive aliases. Raw values remain bounded by the
// authenticated envelope limit and only scalar declared fields are accepted.
func parseReceiptCallback(body []byte) (delivery.ReceiptRecordRequest, error) {
	invalid := func() (delivery.ReceiptRecordRequest, error) {
		return delivery.ReceiptRecordRequest{}, delivery.ErrInvalidInput
	}
	if !utf8.Valid(body) {
		return invalid()
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return invalid()
	}
	var q delivery.ReceiptRecordRequest
	var seen uint8
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return invalid()
		}
		name, ok := token.(string)
		if !ok {
			return invalid()
		}
		var bit uint8
		var target any
		var observed string
		switch name {
		case "tenant_id":
			bit, target = 1, &q.TenantID
		case "provider":
			bit, target = 2, &q.Provider
		case "event_id":
			bit, target = 4, &q.ProviderEventID
		case "intent_id":
			bit, target = 8, &q.IntentID
		case "generation":
			bit, target = 16, &q.Generation
		case "status":
			bit, target = 32, &q.Status
		case "observed_at":
			bit, target = 64, &observed
		default:
			return invalid()
		}
		if seen&bit != 0 {
			return invalid()
		}
		seen |= bit
		if decoder.Decode(target) != nil {
			return invalid()
		}
		if bit == 64 {
			q.ObservedAt, err = time.Parse(time.RFC3339Nano, observed)
			if err != nil || !receiptUTCTime(q.ObservedAt) || q.ObservedAt.Format(time.RFC3339Nano) != observed {
				return invalid()
			}
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || seen != 127 {
		return invalid()
	}
	if _, err := decoder.Token(); err != io.EOF {
		return invalid()
	}
	// Workflow command identity is owned by the kernel, not an unsigned callback
	// idempotency field. Event identity supplies a normalized bounded core value.
	digest := sha256.Sum256([]byte(q.ProviderEventID))
	q.IdempotencyKey = hex.EncodeToString(digest[:])
	if q.Validate() != nil {
		return invalid()
	}
	return q, nil
}
