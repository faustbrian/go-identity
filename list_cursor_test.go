package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUserListCursorRejectsTamperingAndMalformedSignedClaims(t *testing.T) {
	s, _, req := newListFixture(t)
	page, err := s.UserList(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	binding, now := listBinding(req, s.config), queryClock{}.Now()
	claims, err := s.listConfig.openCursor(page.NextCursor, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", strings.Repeat("x", 1025), "not+base64", "AA", page.NextCursor + "=", page.NextCursor[:len(page.NextCursor)-1] + "!"} {
		if _, err := s.listConfig.openCursor(token, binding, now); err == nil || err.Error() != "identity: invalid input" {
			t.Fatal("invalid cursor admitted or leaked")
		}
	}
	raw, _ := base64.RawURLEncoding.DecodeString(page.NextCursor)
	raw[0] = 2
	if _, err := s.listConfig.openCursor(base64.RawURLEncoding.EncodeToString(raw), binding, now); err == nil {
		t.Fatal("unknown version admitted")
	}
	raw, _ = base64.RawURLEncoding.DecodeString(page.NextCursor)
	raw[len(raw)-1] ^= 1
	if _, err := s.listConfig.openCursor(base64.RawURLEncoding.EncodeToString(raw), binding, now); err == nil {
		t.Fatal("tampered signature admitted")
	}
	for name, change := range map[string]func(*cursorClaims){
		"wrong binding":     func(c *cursorClaims) { c.Binding[0] ^= 1 },
		"future issuance":   func(c *cursorClaims) { c.Issued = now.Add(time.Second).UnixNano() },
		"invalid issuance":  func(c *cursorClaims) { c.Issued = 0 },
		"expired":           func(c *cursorClaims) { c.Expires = now.UnixNano() },
		"reversed interval": func(c *cursorClaims) { c.Issued = now.Add(-time.Second).UnixNano(); c.Expires = c.Issued },
		"extended interval": func(c *cursorClaims) { c.Expires = c.Issued + int64(2*time.Minute) },
		"invalid snapshot":  func(c *cursorClaims) { c.Cursor.snapshot = "invalid" },
		"invalid position":  func(c *cursorClaims) { c.Cursor.position = 0 },
		"invalid last id":   func(c *cursorClaims) { c.Last = "bad id" },
	} {
		t.Run(name, func(t *testing.T) {
			c := claims
			change(&c)
			if _, err := s.listConfig.openCursor(s.listConfig.sealCursor(c), binding, now); err == nil {
				t.Fatal("malformed signed claims admitted")
			}
		})
	}
	wire := cursorWire{claims.Binding, claims.Cursor.snapshot, claims.Cursor.position, claims.Issued, claims.Expires, claims.Last}
	canonical, _ := json.Marshal(wire)
	for _, body := range [][]byte{[]byte("not JSON"), []byte(`{"Unknown":1}`), append(append([]byte{}, canonical...), ' '), append(append([]byte{}, canonical...), []byte(`{}`)...)} {
		token := signedCursorBody(s.listConfig, body)
		if _, err := s.listConfig.openCursor(token, binding, now); err == nil {
			t.Fatal("malformed authenticated JSON admitted")
		}
	}
	// A valid outer MAC must not bypass authenticated encryption.
	raw, _ = base64.RawURLEncoding.DecodeString(page.NextCursor)
	raw[5] ^= 1
	_, key := s.listConfig.cursorKeys()
	mac := hmac.New(sha256.New, key)
	mac.Write(raw[:len(raw)-32])
	copy(raw[len(raw)-32:], mac.Sum(nil))
	if _, err := s.listConfig.openCursor(base64.RawURLEncoding.EncodeToString(raw), binding, now); err == nil {
		t.Fatal("damaged authenticated ciphertext admitted")
	}
	other := s.listConfig
	other.CursorKey[0] ^= 1
	if _, err := other.openCursor(page.NextCursor, binding, now); err == nil {
		t.Fatal("rotated key retained old cursor")
	}
}

func TestUserListCursorRoundTripsMaximumCanonicalIDs(t *testing.T) {
	for _, id := range []UserID{UserID(strings.Repeat("&", 128)), UserID(strings.Repeat("\\", 128)), UserID(strings.Repeat("\u2028", 42))} {
		s, repo, req := newListFixture(t)
		repo.fn = func(_ context.Context, q ListUsersQuery) (UserPage, error) {
			if q.Cursor == (Cursor{}) {
				next, _ := NewCursor("AQEBAQEBAQEBAQEBAQEBAQ", 1)
				return UserPage{Users: []User{{ID: id, TenantID: "tenant-a", Status: StatusActive, Version: 1}}, Next: next}, nil
			}
			return UserPage{}, nil
		}
		first, err := s.UserList(context.Background(), req)
		if err != nil || len(first.Users) != 1 || len(first.NextCursor) > 1024 {
			t.Fatal("valid maximum canonical ID produced unusable cursor")
		}
		req.Cursor = first.NextCursor
		if _, err := s.UserList(context.Background(), req); err != nil || repo.calls != 2 {
			t.Fatal("maximum canonical ID failed cursor round trip", err)
		}
	}
}

func signedCursorBody(config UserListConfig, body []byte) string {
	aead, key := config.cursorKeys()
	signed := append([]byte{1}, aead.Seal(nil, nil, body, []byte(cursorPurpose))...)
	mac := hmac.New(sha256.New, key)
	mac.Write(signed)
	return base64.RawURLEncoding.EncodeToString(append(signed, mac.Sum(nil)...))
}

func TestUserListCursorRejectsAlternativeBase64Encodings(t *testing.T) {
	s, _, req := newListFixture(t)
	page, err := s.UserList(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{page.NextCursor + "\n", page.NextCursor[:10] + "\r\n" + page.NextCursor[10:]} {
		req.Cursor = token
		got, err := s.UserList(context.Background(), req)
		requireNoListOutput(t, got, err)
	}
}

func FuzzUserListCursorAdmission(f *testing.F) {
	config := UserListConfig{CursorKey: [32]byte{1}, CursorTTL: time.Minute}
	for _, token := range []string{"", "invalid", "\xff", strings.Repeat("x", 1024), strings.Repeat("x", 1025)} {
		f.Add(token)
	}
	f.Fuzz(func(t *testing.T, token string) {
		claims, err := config.openCursor(token, [32]byte{}, queryClock{}.Now())
		if err != nil {
			if err.Error() != "identity: invalid input" {
				t.Fatal("cursor error leaked")
			}
			return
		}
		if claims.Cursor.Position() == 0 || claims.Expires <= (queryClock{}).Now().UnixNano() {
			t.Fatal("unbounded continuation admitted")
		}
	})
}

type concurrentDirectory struct{}

func (concurrentDirectory) Get(context.Context, GetUserQuery) (User, error) {
	return User{ID: "user-a", TenantID: "tenant-a", Status: StatusActive, Version: 1}, nil
}
func (concurrentDirectory) List(context.Context, ListUsersQuery) (UserPage, error) {
	next, _ := NewCursor("AQEBAQEBAQEBAQEBAQEBAQ", 1)
	return UserPage{Users: []User{{ID: "user-a", TenantID: "tenant-a", Status: StatusActive, Version: 1}}, Next: next}, nil
}

func TestUserListConcurrentReadersOwnResultsAndConfiguration(t *testing.T) {
	s, _, req := newListFixture(t)
	config := s.listConfig
	service, err := NewUserDirectoryService(concurrentDirectory{}, s.authorize, s.redact, s.config, config)
	if err != nil {
		t.Fatal(err)
	}
	config.CursorKey[0] = 2
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := service.UserList(context.Background(), req)
			if err != nil || len(got.Users) != 1 || got.NextCursor == "" {
				t.Error("concurrent query failed")
				return
			}
			binding := listBinding(req, s.config)
			if _, err := service.listConfig.openCursor(got.NextCursor, binding, queryClock{}.Now()); err != nil {
				t.Error("caller config mutation changed key")
			}
			got.Users[0].ID = "mutated"
		}()
	}
	wg.Wait()
	got, err := service.UserList(context.Background(), req)
	if err != nil || got.Users[0].ID != "user-a" {
		t.Fatal("result aliases another reader")
	}
}
