package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/apikey"
)

func TestMetadataCursorIsOnlyABoundedScopedPosition(t *testing.T) {
	scope := [32]byte{1}
	for _, id := range []apikey.KeyID{"canonical-key", "01ARZ3NDEKTSV4RRFFQ69G5FAV", apikey.KeyID(strings.Repeat("k", 128))} { // gitleaks:allow -- Public metadata cursor positions, not credentials.
		cursor := encodeMetadataCursor(id, scope)
		got, err := decodeMetadataCursor(cursor, scope)
		if err != nil || got != id || len(cursor) > 512 {
			t.Fatal("bounded canonical key position did not round trip", err)
		}
		if _, err := decodeMetadataCursor(cursor, [32]byte{2}); !errors.Is(err, apikey.ErrInvalid) {
			t.Fatal("foreign scope cursor accepted")
		}
	}
	if got, err := decodeMetadataCursor("", scope); err != nil || got != "" {
		t.Fatal("initial empty position rejected")
	}
	badVersion, _ := base64.RawURLEncoding.DecodeString(encodeMetadataCursor("key", scope))
	badVersion[0] = 2
	for _, cursor := range []string{
		"malformed", strings.Repeat("x", 513),
		base64.RawURLEncoding.EncodeToString(badVersion),
		encodeMetadataCursor("invalid key", scope),
		encodeMetadataCursor(apikey.KeyID(strings.Repeat("k", 129)), scope),
		encodeMetadataCursor("key", scope) + "=",
	} {
		if _, err := decodeMetadataCursor(cursor, scope); !errors.Is(err, apikey.ErrInvalid) {
			t.Fatal("ambiguous, unsupported or unbounded cursor accepted")
		}
	}
	// Positions are deliberately constructible without a secret or authority.
	// Only actual current native owner/profile checks can authorize a page.
	if got, err := decodeMetadataCursor(encodeMetadataCursor("not-a-stored-key", scope), scope); err != nil || got != "not-a-stored-key" {
		t.Fatal("paging position was incorrectly treated as credential authority")
	}
}

func TestMetadataMethodsRejectAbsentNativeOwners(t *testing.T) {
	var service *Service
	if out, err := service.Get(context.Background(), apikey.GetRequest{}); !errors.Is(err, apikey.ErrInvalid) || out.Record.ID != "" {
		t.Fatal("absent native reader produced a record")
	}
	if out, err := service.List(context.Background(), apikey.ListRequest{}); !errors.Is(err, apikey.ErrInvalid) || out.Records != nil || out.NextCursor != "" {
		t.Fatal("absent native reader produced a page")
	}
}

func FuzzMetadataCursor(f *testing.F) {
	scope := [32]byte{1}
	for _, cursor := range []string{"", "malformed", encodeMetadataCursor("canonical-key", scope), encodeMetadataCursor("invalid key", scope)} {
		f.Add(cursor)
	}
	f.Fuzz(func(t *testing.T, cursor string) {
		position, err := decodeMetadataCursor(cursor, scope)
		if err != nil || cursor == "" {
			return
		}
		if _, err := apikey.ParseKeyID(string(position)); err != nil || encodeMetadataCursor(position, scope) != cursor || len(cursor) > 512 {
			t.Fatal("accepted cursor did not preserve its canonical bounded position")
		}
	})
}
