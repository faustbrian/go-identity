package postgres

import (
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestProviderDisableCascadeWindow(t *testing.T) {
	for _, tt := range []struct {
		name     string
		in, want time.Duration
	}{
		{"default", 0, 7 * 24 * time.Hour},
		{"minimum", time.Hour, time.Hour},
		{"maximum", 30 * 24 * time.Hour, 30 * 24 * time.Hour},
		{"negative", -time.Hour, 0},
		{"below minimum", time.Hour - time.Second, 0},
		{"fractional second", time.Hour + time.Microsecond, 0},
		{"above maximum", 30*24*time.Hour + time.Second, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := providerDisableCascadeWindow(tt.in)
			if tt.want == 0 {
				var invalid identity.InvalidInputError
				if got != 0 || !errors.As(err, &invalid) {
					t.Fatalf("invalid deadline window: got %v, %v", got, err)
				}
			} else if got != tt.want || err != nil {
				t.Fatalf("window = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}
