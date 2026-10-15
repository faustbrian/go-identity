package postgres

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"strconv"

	"github.com/faustbrian/go-identity/delivery"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Cursor custody is separate from expired send payloads: an unresolved provider
// effect may require lookup after its original bearer expires. No expiry is
// renewed here and possession of cursor custody grants no execution authority.
type reconciliationCursorScope struct {
	Deployment, Tenant, Subject, Effect, Provider string
	ProviderVersion                               uint64
	Generation                                    uint32
	Step                                          int64
	Digest                                        [32]byte
}
type reconciliationCursorEnvelope struct {
	KeyID      string
	KeyVersion uint32
	Wire       []byte
}

func (reconciliationCursorEnvelope) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("delivery.postgres.cursor(redacted)"))
}
func (reconciliationCursorEnvelope) LogValue() slog.Value {
	return slog.StringValue("delivery.postgres.cursor(redacted)")
}

func reconciliationCursorContext(s reconciliationCursorScope) (secretenvelope.Context, error) {
	for _, id := range []string{s.Deployment, s.Tenant, s.Subject, s.Effect, s.Provider} {
		if !safeID(id, false) {
			return secretenvelope.Context{}, delivery.ErrInvalidInput
		}
	}
	if s.ProviderVersion == 0 || s.Generation == 0 || s.Step < 1 || s.Step == math.MaxInt64 || s.Digest == ([32]byte{}) {
		return secretenvelope.Context{}, delivery.ErrInvalidInput
	}
	return secretenvelope.NewContext(map[string]string{
		"profile": "identity-delivery-query-cursor-v1", "deployment": s.Deployment, "tenant": s.Tenant, "subject": s.Subject, "effect": s.Effect, "provider": s.Provider,
		"provider_version": strconv.FormatUint(s.ProviderVersion, 10), "generation": strconv.FormatUint(uint64(s.Generation), 10), "step": strconv.FormatInt(s.Step, 10), "cursor_digest": hex.EncodeToString(s.Digest[:]),
	})
}
func validReconciliationCursor(cursor string) bool {
	if len(cursor) < 1 || len(cursor) > 512 {
		return false
	}
	for i := range len(cursor) {
		if cursor[i] < 33 || cursor[i] > 126 {
			return false
		}
	}
	return true
}
func reconciliationCursorDigest(key [32]byte, s reconciliationCursorScope, cursor string) [32]byte {
	if cursor == "" {
		return [32]byte{}
	}
	return custodyMAC(key, "identity-delivery-query-cursor-digest-v1", keyedFields(s.Deployment, s.Tenant, s.Subject, s.Effect, s.Provider, strconv.FormatUint(s.ProviderVersion, 10), strconv.FormatUint(uint64(s.Generation), 10), strconv.FormatInt(s.Step, 10)), []byte(cursor))
}

// Public tokens are deterministic scoped progress commitments, never raw
// provider cursors. Their replay identity survives ciphertext terminal erasure.
func reconciliationCursorToken(key [32]byte, s reconciliationCursorScope) string {
	if s.Digest == ([32]byte{}) {
		return ""
	}
	aad, err := reconciliationCursorContext(s)
	if err != nil {
		return ""
	}
	mac := custodyMAC(key, "identity-delivery-query-cursor-token-v1", aad.AdditionalData(), nil)
	return base64.RawURLEncoding.EncodeToString(mac[:])
}
func sealReconciliationCursor(ctx context.Context, c *payloadCodec, s reconciliationCursorScope, cursor, keyID string, version uint32) (out reconciliationCursorEnvelope, err error) {
	if ctx == nil || c == nil || c.service == nil || !validReconciliationCursor(cursor) || !safeID(keyID, false) {
		return out, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	key, ok := c.keys[version]
	if !ok {
		return out, delivery.ErrUnavailable
	}
	aad, err := reconciliationCursorContext(s)
	if err != nil {
		return out, err
	}
	w, stop := context.WithTimeout(ctx, c.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			out = reconciliationCursorEnvelope{}
			err = delivery.ErrUnavailable
		}
	}()
	plain := []byte(cursor)
	defer clear(plain)
	envelope, err := c.service.Encrypt(w, secretenvelope.EncryptRequest{Plaintext: plain, KeyReference: keyID, Context: aad})
	if w.Err() != nil {
		return out, w.Err()
	}
	if err != nil {
		return out, delivery.ErrUnavailable
	}
	wire, err := envelope.MarshalBinary()
	if err != nil || envelope.KeyReference() != keyID || len(wire) > 8192-32 {
		return out, delivery.ErrUnavailable
	}
	// Authenticating retained key ID/version locally lets the protected phase
	// verify custody without calling a key provider inside the SQL transaction.
	mac := custodyMAC(key, "identity-delivery-query-custody-v1", append(aad.AdditionalData(), keyedFields(keyID, strconv.FormatUint(uint64(version), 10))...), wire)
	wire = append(wire, mac[:]...)
	return reconciliationCursorEnvelope{KeyID: keyID, KeyVersion: version, Wire: wire}, nil
}
func verifyReconciliationCursor(c *payloadCodec, s reconciliationCursorScope, v reconciliationCursorEnvelope) error {
	if c == nil || c.service == nil || !safeID(v.KeyID, false) || len(v.Wire) < 33 || len(v.Wire) > 8192 {
		return delivery.ErrInvalidInput
	}
	key, ok := c.keys[v.KeyVersion]
	if !ok {
		return delivery.ErrUnavailable
	}
	aad, err := reconciliationCursorContext(s)
	if err != nil {
		return err
	}
	end := len(v.Wire) - 32
	mac := custodyMAC(key, "identity-delivery-query-custody-v1", append(aad.AdditionalData(), keyedFields(v.KeyID, strconv.FormatUint(uint64(v.KeyVersion), 10))...), v.Wire[:end])
	if !hmac.Equal(mac[:], v.Wire[end:]) {
		return delivery.ErrForbidden
	}
	envelope, err := secretenvelope.ParseEnvelope(v.Wire[:end])
	if err != nil || envelope.KeyReference() != v.KeyID {
		return delivery.ErrForbidden
	}
	return nil
}
func openReconciliationCursor(ctx context.Context, c *payloadCodec, s reconciliationCursorScope, v reconciliationCursorEnvelope) (cursor string, err error) {
	if ctx == nil {
		return "", delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := verifyReconciliationCursor(c, s, v); err != nil {
		return "", err
	}
	aad, _ := reconciliationCursorContext(s)
	envelope, _ := secretenvelope.ParseEnvelope(v.Wire[:len(v.Wire)-32])
	w, stop := context.WithTimeout(ctx, c.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			cursor = ""
			err = delivery.ErrUnavailable
		}
	}()
	plain, err := c.service.Decrypt(w, secretenvelope.DecryptRequest{Envelope: envelope, Context: aad})
	defer clear(plain)
	if w.Err() != nil {
		return "", w.Err()
	}
	if err != nil {
		return "", delivery.ErrUnavailable
	}
	if len(plain) < 1 || len(plain) > 512 {
		return "", delivery.ErrInvalidInput
	}
	cursor = string(plain)
	if !validReconciliationCursor(cursor) {
		return "", delivery.ErrInvalidInput
	}
	return cursor, nil
}
