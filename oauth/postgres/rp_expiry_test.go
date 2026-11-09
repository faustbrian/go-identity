package postgres

import (
	"context"
	"testing"
	"time"
)

func TestRPExpiryCursorRoundTripAndInvalidOwner(t *testing.T) {
	position := rpExpiryPosition{expires: time.Unix(1800000000, 123000).UTC(), tenant: "tenant-a", id: "transaction-a"}
	got, err := parseRPExpiryCursor(position.cursor())
	if err != nil || got != position {
		t.Fatal("expiry pagination changed its exact primary position", err)
	}
	for _, service := range []*LinkService{nil, {}} {
		if _, _, err := service.EraseExpiredUnused(context.Background(), 1, ""); err == nil {
			t.Fatal("uninitialized service admitted expiry maintenance")
		}
	}
}

func FuzzRPExpiryCursor(f *testing.F) {
	f.Add("")
	f.Add((rpExpiryPosition{expires: time.Unix(1800000000, 0).UTC(), tenant: "tenant-a", id: "transaction-a"}).cursor())
	f.Add("expires=invalid&tenant=a&transaction=b")
	f.Add("expires=1&expires=2&transaction=b")
	f.Fuzz(func(t *testing.T, cursor string) {
		position, err := parseRPExpiryCursor(cursor)
		if err != nil || cursor == "" {
			return
		}
		if len(cursor) > 1024 || position.cursor() != cursor || !rpUTCTime(position.expires) {
			t.Fatal("accepted expiry cursor has no stable bounded primary position")
		}
	})
}
