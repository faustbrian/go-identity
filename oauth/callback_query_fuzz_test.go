package oauth_test

import (
	"context"
	"net/url"
	"testing"

	oauth "github.com/faustbrian/go-identity/oauth"
)

func FuzzQueryCallback(f *testing.F) {
	for _, raw := range []string{
		queryResponse("code=synthetic"), queryResponse("error=access_denied"),
		queryResponse("code=synthetic&%63ode=duplicate"), queryResponse("code=%FF"),
		queryResponse("error=access_denied&error_description=%22"), "code=%",
	} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		profile := queryProfile()
		profile.MaxCodeBytes = 128
		result, err := oauth.ParseQueryCallback(context.Background(), raw, profile)
		defer result.Destroy()
		input, success := result.Input()
		if err != nil {
			if success || result.Denied() {
				t.Fatal("invalid query produced a variant")
			}
			return
		}
		if success == result.Denied() {
			t.Fatal("query variant is ambiguous")
		}
		if success {
			if err := input.Use(context.Background(), func(_ context.Context, code, state []byte) error {
				if len(code) == 0 || len(code) > profile.MaxCodeBytes || len(state) != 43 {
					t.Fatal("unbounded success custody")
				}
				return nil
			}); err != nil {
				t.Fatal("success custody unavailable")
			}
		} else {
			if err := result.UseDeniedState(context.Background(), func(_ context.Context, state []byte) error {
				if len(state) != 43 {
					t.Fatal("unbounded denial state")
				}
				return nil
			}); err != nil {
				t.Fatal("denial state unavailable")
			}
		}
	})
}

func FuzzQueryCallbackCodePreservation(f *testing.F) {
	f.Add([]byte(" synthetic +/=:; code "))
	f.Add([]byte{0x20, 0x7e})
	f.Fuzz(func(t *testing.T, code []byte) {
		if len(code) == 0 || len(code) > 128 {
			t.Skip()
		}
		for _, b := range code {
			if b < 0x20 || b > 0x7e {
				t.Skip()
			}
		}
		profile := queryProfile()
		profile.MaxCodeBytes = 128
		result, err := oauth.ParseQueryCallback(context.Background(), queryResponse("code="+url.QueryEscape(string(code))), profile)
		if err != nil {
			t.Fatal("valid bounded code rejected")
		}
		defer result.Destroy()
		input, success := result.Input()
		if !success {
			t.Fatal("valid code did not produce success")
		}
		if err := input.Use(context.Background(), func(_ context.Context, got, _ []byte) error {
			if string(got) != string(code) {
				t.Fatal("original code changed")
			}
			return nil
		}); err != nil {
			t.Fatal("code borrow unavailable")
		}
	})
}
