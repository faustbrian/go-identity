package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/delivery"
)

func receiptAuthFixture(t *testing.T) (*receiptAuthenticator, receiptSignedInput, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	profile := receiptAuthProfile{Tenant: "tenant", Provider: "test-provider", Version: 1, Actor: "provider-actor", KeyID: "callback-key", Key: [32]byte{9}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	auth, err := newReceiptAuthenticator("test", []receiptAuthProfile{profile}, 16384)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"tenant_id":"tenant","provider":"test-provider","event_id":"event-1","intent_id":"` + strings.Repeat("a", 64) + `","generation":1,"status":4,"observed_at":"2026-10-01T12:00:00Z"}`)
	input := receiptSignedInput{Tenant: "tenant", Provider: "test-provider", Version: 1, KeyID: "callback-key", SignedAt: now, Body: body}
	input.Signature = receiptAuthOracle(t, "test", profile.Key, input)
	return auth, input, now
}

// Independent wire encoder: no production signature helper or parser is used.
func receiptAuthOracle(t *testing.T, deployment string, key [32]byte, input receiptSignedInput) [32]byte {
	t.Helper()
	scope, err := json.Marshal([]string{deployment, input.Tenant, input.Provider, strconv.FormatUint(input.Version, 10), input.KeyID, input.SignedAt.Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("identity-delivery-receipt-hmac-sha256-v1"))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(scope)))
	mac.Write(size[:])
	mac.Write(scope)
	binary.BigEndian.PutUint64(size[:], uint64(len(input.Body)))
	mac.Write(size[:])
	mac.Write(input.Body)
	var sum [32]byte
	copy(sum[:], mac.Sum(nil))
	return sum
}

func TestReceiptAuthenticationBindsExactScopeAndFreshEnvelope(t *testing.T) {
	auth, input, now := receiptAuthFixture(t)
	q, actor, err := auth.verify(context.Background(), input, now)
	if err != nil || actor != "provider-actor" || q.ProviderEventID != "event-1" || q.Generation != 1 || q.Validate() != nil || q.ObservedAt != now.Add(-72*time.Hour) {
		t.Fatal("freshly signed delayed observation rejected", err)
	}
	for _, mutate := range []func(*receiptSignedInput){
		func(q *receiptSignedInput) { q.Body = append(append([]byte{}, q.Body...), ' ') },
		func(q *receiptSignedInput) { q.Tenant = "foreign" },
		func(q *receiptSignedInput) { q.Provider = "foreign" },
		func(q *receiptSignedInput) { q.Version++ },
		func(q *receiptSignedInput) { q.KeyID = "foreign" },
		func(q *receiptSignedInput) { q.SignedAt = q.SignedAt.Add(-time.Second) },
		func(q *receiptSignedInput) { q.Signature[0] ^= 1 },
	} {
		altered := input
		mutate(&altered)
		got, actor, err := auth.verify(context.Background(), altered, now)
		if !errors.Is(err, delivery.ErrForbidden) || actor != "" || got != (delivery.ReceiptRecordRequest{}) {
			t.Fatal("forged evidence admitted", err)
		}
	}
	for _, delta := range []time.Duration{5 * time.Minute, 5*time.Minute + time.Nanosecond, -30*time.Second - time.Nanosecond, 2 * time.Hour} {
		if _, _, err := auth.verify(context.Background(), input, now.Add(delta)); !errors.Is(err, delivery.ErrForbidden) {
			t.Fatal("expired or future envelope admitted", delta, err)
		}
	}
}

func TestReceiptAuthenticationClosedBoundedParser(t *testing.T) {
	auth, input, now := receiptAuthFixture(t)
	original := string(input.Body)
	for _, body := range []string{
		original + `{}`, strings.Replace(original, `"generation":1`, `"generation":1,"generation":1`, 1),
		strings.Replace(original, `"generation":1`, `"Generation":1`, 1),
		strings.Replace(original, `"generation":1`, `"generation":1,"extra":true`, 1),
		strings.Replace(original, `"generation":1,`, "", 1),
		strings.Replace(original, `"generation":1`, `"generation":1.0`, 1),
		strings.Replace(original, `"generation":1`, `"generation":null`, 1),
		strings.Replace(original, `"tenant_id":"tenant"`, `"tenant_id":"foreign"`, 1),
		strings.Replace(original, `"event-1"`, `"event-\ud800"`, 1),
		"[]", "null", "{", string([]byte{0xff}), strings.Repeat(" ", 16385),
	} {
		altered := input
		altered.Body = []byte(body)
		altered.Signature = receiptAuthOracle(t, "test", [32]byte{9}, altered)
		got, actor, err := auth.verify(context.Background(), altered, now)
		if err == nil || got != (delivery.ReceiptRecordRequest{}) || actor != "" {
			t.Fatal("invalid callback admitted")
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := auth.verify(cancelled, input, now); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}

func TestReceiptAuthenticationCopiesAndValidatesProfiles(t *testing.T) {
	auth, input, now := receiptAuthFixture(t)
	_ = auth
	profile := receiptAuthProfile{Tenant: "tenant", Provider: "test-provider", Version: 1, Actor: "provider-actor", KeyID: "callback-key", Key: [32]byte{9}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	profiles := []receiptAuthProfile{profile}
	auth, err := newReceiptAuthenticator("test", profiles, 16384)
	if err != nil {
		t.Fatal(err)
	}
	profiles[0].Key = [32]byte{}
	if _, _, err := auth.verify(context.Background(), input, now); err != nil {
		t.Fatal("caller mutation changed owned credentials", err)
	}
	for _, change := range []func(*receiptAuthProfile){
		func(p *receiptAuthProfile) { p.Key = [32]byte{} },
		func(p *receiptAuthProfile) { p.Version = 0 },
		func(p *receiptAuthProfile) { p.Actor = "" },
		func(p *receiptAuthProfile) { p.NotBefore = p.NotAfter },
		func(p *receiptAuthProfile) { p.NotAfter = time.Time{} },
	} {
		invalid := profile
		change(&invalid)
		if got, err := newReceiptAuthenticator("test", []receiptAuthProfile{invalid}, 16384); got != nil || !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal("invalid profile accepted", err)
		}
	}
	if got, err := newReceiptAuthenticator("test", []receiptAuthProfile{profile, profile}, 16384); got != nil || !errors.Is(err, delivery.ErrInvalidInput) {
		t.Fatal("ambiguous key selection accepted", err)
	}
}

func TestReceiptAuthenticationKeyRotationAndExactBoundaries(t *testing.T) {
	auth, input, now := receiptAuthFixture(t)
	profile := auth.profiles[0]
	successor := profile
	successor.KeyID, successor.Key = "successor", [32]byte{11}
	successor.NotBefore, successor.NotAfter = now, now.Add(2*time.Hour)
	profiles := []receiptAuthProfile{profile, successor}
	auth, err := newReceiptAuthenticator("test", profiles, 256)
	if err != nil {
		t.Fatal(err)
	}
	for _, signing := range []time.Time{now.Add(-5*time.Minute + time.Nanosecond), now.Add(30 * time.Second), profile.NotBefore} {
		candidate := input
		candidate.SignedAt = signing
		candidate.Signature = receiptAuthOracle(t, "test", profile.Key, candidate)
		observation := now
		if signing == profile.NotBefore {
			observation = signing
		}
		if _, _, err := auth.verify(context.Background(), candidate, observation); err != nil {
			t.Fatal("valid boundary denied", err)
		}
	}
	candidate := input
	candidate.KeyID = successor.KeyID
	candidate.Signature = receiptAuthOracle(t, "test", successor.Key, candidate)
	if _, _, err := auth.verify(context.Background(), candidate, now); err != nil {
		t.Fatal("rotated key rejected", err)
	}
	// Old observation does not let an expired credential recover authority.
	candidate = input
	candidate.SignedAt = profile.NotAfter
	candidate.Signature = receiptAuthOracle(t, "test", profile.Key, candidate)
	if _, _, err := auth.verify(context.Background(), candidate, profile.NotAfter); !errors.Is(err, delivery.ErrForbidden) {
		t.Fatal("retired key admitted", err)
	}
	// Domain/deployment binding cannot be omitted by a valid sender.
	candidate = input
	candidate.Signature = receiptAuthOracle(t, "foreign", profile.Key, candidate)
	if _, _, err := auth.verify(context.Background(), candidate, now); !errors.Is(err, delivery.ErrForbidden) {
		t.Fatal("cross-deployment signature admitted", err)
	}
}

func FuzzReceiptCallbackClosedParser(f *testing.F) {
	f.Add([]byte(`{"tenant_id":"tenant","provider":"test-provider","event_id":"event","intent_id":"intent","generation":1,"status":4,"observed_at":"2026-10-04T12:00:00Z"}`))
	f.Add([]byte(`{"generation":1,"generation":2}`))
	f.Add([]byte(`{"event_id":"\ud800"}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 65536 {
			t.Skip()
		}
		q, err := parseReceiptCallback(body)
		if err == nil && q.Validate() != nil {
			t.Fatal("parser returned invalid normalized evidence")
		}
		if err != nil && q != (delivery.ReceiptRecordRequest{}) {
			t.Fatal("parser leaked partial evidence")
		}
	})
}
