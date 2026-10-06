package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestCaptchaDomainWorkRejectsZeroAndSerialization(t *testing.T) {
	p := &captchaUseReservationProbe{}
	read, write, release := CaptchaApplyWork{}, CaptchaFinalizeWork{}, CaptchaReleaseWork{}
	for _, binding := range []func(CaptchaUseReservationContributor) (CaptchaUseReservationBinding, error){read.Binding, write.Binding, release.Binding} {
		if _, err := binding(p); err == nil {
			t.Fatal("zero disclosed custody")
		}
	}
	for _, query := range []func(context.Context, string, ...any) (*WorkRows, error){read.Query, write.Query, release.Query} {
		if _, err := query(context.Background(), "SELECT 1"); err == nil {
			t.Fatal("zero read primary")
		}
	}
	for _, exec := range []func(context.Context, string, ...any) (int64, error){write.Exec, release.Exec} {
		if _, err := exec(context.Background(), "SELECT 1"); err == nil {
			t.Fatal("zero mutated primary")
		}
	}
	for _, value := range []any{read, write, release} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("serialized invocation authority")
		}
		if !strings.Contains(fmt.Sprintf("%#v", value), "redacted") {
			t.Fatal("exposed invocation")
		}
	}
}
