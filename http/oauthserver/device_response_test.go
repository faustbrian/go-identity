package oauthserverhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/faustbrian/go-oauth-server/device"
)

func deviceResponseToken(t *testing.T, wire string) oauth.Token {
	t.Helper()
	token, err := oauth.ParseToken(wire)
	if err != nil {
		t.Fatal("invalid synthetic token fixture")
	}
	return token
}

func deviceResponseAuthorization(t *testing.T, now time.Time) device.Authorization {
	t.Helper()
	return device.Authorization{
		Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted, CommandID: "synthetic-device-command"},
		DeviceCode: deviceResponseToken(t, strings.Repeat("A", 43)),
		UserCode:   "BCDF-GHJK", VerificationURI: "https://issuer.example/device",
		VerificationURIComplete: "https://issuer.example/device?user_code=BCDF-GHJK",
		ExpiresAt:               now.Add(time.Minute), Interval: 5 * time.Second,
	}
}

func deviceResponsePollResult(t *testing.T, now time.Time, refresh bool) device.PollResult {
	t.Helper()
	completion := oauth.Completion{Outcome: identity.CommitOutcomeCommitted, CommandID: "synthetic-poll-command"}
	tokens := oauth.TokenResult{
		Outcome: completion.Outcome, CommandID: completion.CommandID,
		AccessToken: deviceResponseToken(t, strings.Repeat("A", 43)),
		ExpiresAt:   now.Add(30 * time.Second), Resource: "https://resource.example",
		Scopes: []string{"identity:read", "identity:write"},
	}
	if refresh {
		tokens.RefreshToken = deviceResponseToken(t, strings.Repeat("E", 42)+"A")
	}
	return device.PollResult{Completion: completion, Tokens: tokens, Interval: 5 * time.Second}
}

func assertDeviceResponse(t *testing.T, w *httptest.ResponseRecorder, status int, expected map[string]any) {
	t.Helper()
	if w.Code != status || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatal("unexpected status or response security headers", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || !reflect.DeepEqual(body, expected) {
		t.Fatal("unexpected public device response shape")
	}
}

func TestDeviceAuthorizationResponseRevealsOnlyFreshAcknowledgedCodeOnce(t *testing.T) {
	now := time.Unix(1800000000, 0)
	out := deviceResponseAuthorization(t, now)
	r := httptest.NewRequest(http.MethodPost, "https://issuer.example/device_authorization", nil)
	w := httptest.NewRecorder()
	writeDeviceAuthorization(w, r, now, out, nil)
	assertDeviceResponse(t, w, 200, map[string]any{
		"device_code": strings.Repeat("A", 43), "user_code": out.UserCode,
		"verification_uri": out.VerificationURI, "verification_uri_complete": out.VerificationURIComplete,
		"expires_in": float64(60), "interval": float64(5),
	})
	second := httptest.NewRecorder()
	writeDeviceAuthorization(second, r, now, out, nil)
	assertDeviceResponse(t, second, 503, map[string]any{"error": "temporarily_unavailable"})
}

func TestDeviceAuthorizationResponseDeniesBeforeRevealingCustody(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, tc := range []struct {
		name   string
		change func(*device.Authorization)
		cancel bool
		err    error
	}{
		{name: "unknown", change: func(out *device.Authorization) { out.Completion.Outcome = identity.CommitOutcomeUnknown }},
		{name: "not committed", change: func(out *device.Authorization) { out.Completion.Outcome = identity.CommitOutcomeNotCommitted }},
		{name: "replay", change: func(out *device.Authorization) { out.Completion.Replayed = true }},
		{name: "missing acknowledgment", change: func(out *device.Authorization) { out.Completion.CommandID = "" }},
		{name: "expired", change: func(out *device.Authorization) { out.ExpiresAt = now }},
		{name: "partial", change: func(out *device.Authorization) { out.UserCode = "" }},
		{name: "unbounded interval", change: func(out *device.Authorization) { out.Interval = 61 * time.Second }},
		{name: "fractional interval", change: func(out *device.Authorization) { out.Interval = 5500 * time.Millisecond }},
		{name: "oversized projection", change: func(out *device.Authorization) { out.VerificationURIComplete = strings.Repeat("x", 17000) }},
		{name: "cancelled", cancel: true},
		{name: "error with partial result", err: errors.New("sensitive backend diagnostic")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := deviceResponseAuthorization(t, now)
			if tc.change != nil {
				tc.change(&out)
			}
			r := httptest.NewRequest(http.MethodPost, "https://issuer.example/device_authorization", nil)
			if tc.cancel {
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			w := httptest.NewRecorder()
			writeDeviceAuthorization(w, r, now, out, tc.err)
			assertDeviceResponse(t, w, 503, map[string]any{"error": "temporarily_unavailable"})
			if _, err := out.DeviceCode.Reveal(); err != nil {
				t.Fatal("denial consumed device code before output validation")
			}
		})
	}
}

func TestDevicePollResponseDeliversSelectedTokensOnceWithoutIDToken(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, refresh := range []bool{false, true} {
		t.Run(fmt.Sprint("refresh=", refresh), func(t *testing.T) {
			out := deviceResponsePollResult(t, now, refresh)
			r := httptest.NewRequest(http.MethodPost, "https://issuer.example/token", nil)
			w := httptest.NewRecorder()
			writeDevicePoll(w, r, now, out, nil)
			want := map[string]any{"access_token": strings.Repeat("A", 43), "token_type": "Bearer", "expires_in": float64(30), "scope": "identity:read identity:write"}
			if refresh {
				want["refresh_token"] = strings.Repeat("E", 42) + "A"
			}
			assertDeviceResponse(t, w, 200, want)
			second := httptest.NewRecorder()
			writeDevicePoll(second, r, now, out, nil)
			assertDeviceResponse(t, second, 503, map[string]any{"error": "temporarily_unavailable"})
		})
	}
}

func TestDevicePollResponseDeniesInvalidCompletionBeforeTokenReveal(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, tc := range []struct {
		name   string
		change func(*device.PollResult)
		cancel bool
	}{
		{name: "unknown outer", change: func(out *device.PollResult) { out.Completion.Outcome = identity.CommitOutcomeUnknown }},
		{name: "replayed outer", change: func(out *device.PollResult) { out.Completion.Replayed = true }},
		{name: "unacknowledged outer", change: func(out *device.PollResult) { out.Completion.CommandID = "" }},
		{name: "unknown tokens", change: func(out *device.PollResult) { out.Tokens.Outcome = identity.CommitOutcomeUnknown }},
		{name: "replayed tokens", change: func(out *device.PollResult) { out.Tokens.Replayed = true }},
		{name: "different acknowledgment", change: func(out *device.PollResult) { out.Tokens.CommandID = "other-command" }},
		{name: "expired", change: func(out *device.PollResult) { out.Tokens.ExpiresAt = now }},
		{name: "partial scopes", change: func(out *device.PollResult) { out.Tokens.Scopes = nil }},
		{name: "oversized scopes", change: func(out *device.PollResult) { out.Tokens.Scopes = []string{strings.Repeat("s", 17000)} }},
		{name: "scope injection", change: func(out *device.PollResult) { out.Tokens.Scopes = []string{"identity:read identity:write"} }},
		{name: "exchange contamination", change: func(out *device.PollResult) { out.Tokens.IssuedTokenType = oauth.AccessTokenType }},
		{name: "oidc contamination", change: func(out *device.PollResult) { out.Tokens.IDToken, _ = oauth.ParseIDToken("synthetic.header.signature") }},
		{name: "cancelled", cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := deviceResponsePollResult(t, now, true)
			if tc.change != nil {
				tc.change(&out)
			}
			r := httptest.NewRequest(http.MethodPost, "https://issuer.example/token", nil)
			if tc.cancel {
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			w := httptest.NewRecorder()
			writeDevicePoll(w, r, now, out, nil)
			assertDeviceResponse(t, w, 503, map[string]any{"error": "temporarily_unavailable"})
			if _, err := out.Tokens.AccessToken.Reveal(); err != nil {
				t.Fatal("denial consumed access custody")
			}
			if _, err := out.Tokens.RefreshToken.Reveal(); err != nil {
				t.Fatal("denial consumed refresh custody")
			}
		})
	}
}

func TestDevicePollResponseMapsProtocolConditionsWithoutPartialCredentials(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{device.ErrAuthorizationPending, 400, "authorization_pending"},
		{device.ErrSlowDown, 400, "slow_down"},
		{device.ErrAccessDenied, 400, "access_denied"},
		{device.ErrExpiredToken, 400, "expired_token"},
		{device.ErrInvalidRequest, 400, "invalid_request"},
		{oauth.ErrInvalidClient, 401, "invalid_client"},
		{oauth.ErrInvalidScope, 400, "invalid_scope"},
		{device.ErrUnavailable, 503, "temporarily_unavailable"},
		{errors.New("sensitive backend diagnostic"), 503, "temporarily_unavailable"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			out := deviceResponsePollResult(t, now, true)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "https://issuer.example/token", nil)
			writeDevicePoll(w, r, now, out, fmt.Errorf("redacted wrapper: %w", tc.err))
			assertDeviceResponse(t, w, tc.status, map[string]any{"error": tc.code})
			if tc.status == 401 && w.Header().Get("WWW-Authenticate") != `Basic realm="oauth2"` {
				t.Fatal("missing client authentication challenge")
			}
			if _, err := out.Tokens.AccessToken.Reveal(); err != nil {
				t.Fatal("error consumed partial access custody")
			}
			if _, err := out.Tokens.RefreshToken.Reveal(); err != nil {
				t.Fatal("error consumed partial refresh custody")
			}
		})
	}
}

func TestDevicePollResponseNeverWritesPartialSuccessWhenOneCustodyWasRevealed(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, already := range []string{"access", "refresh"} {
		t.Run(already, func(t *testing.T) {
			out := deviceResponsePollResult(t, now, true)
			if already == "access" {
				_, _ = out.Tokens.AccessToken.Reveal()
			} else {
				_, _ = out.Tokens.RefreshToken.Reveal()
			}
			w := httptest.NewRecorder()
			writeDevicePoll(w, httptest.NewRequest(http.MethodPost, "https://issuer.example/token", nil), now, out, nil)
			assertDeviceResponse(t, w, 503, map[string]any{"error": "temporarily_unavailable"})
		})
	}
}

func TestDeviceAuthorizationResponseMapsErrorsWithoutRevealingCode(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{device.ErrInvalidRequest, 400, "invalid_request"},
		{device.ErrAccessDenied, 400, "access_denied"},
		{oauth.ErrInvalidClient, 401, "invalid_client"},
		{oauth.ErrInvalidScope, 400, "invalid_scope"},
		{device.ErrUnavailable, 503, "temporarily_unavailable"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			out := deviceResponseAuthorization(t, now)
			w := httptest.NewRecorder()
			writeDeviceAuthorization(w, httptest.NewRequest(http.MethodPost, "https://issuer.example/device_authorization", nil), now, out, tc.err)
			assertDeviceResponse(t, w, tc.status, map[string]any{"error": tc.code})
			if _, err := out.DeviceCode.Reveal(); err != nil {
				t.Fatal("error consumed partial device custody")
			}
		})
	}
}

func TestDeviceResponsesDenyMissingClockAndCancellationOverridesProtocolError(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, cancelRequest := range []bool{false, true} {
		t.Run(fmt.Sprint("cancelled=", cancelRequest), func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://issuer.example/token", nil)
			projectAt := time.Time{}
			var resultErr error
			if cancelRequest {
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
				projectAt = now
				resultErr = device.ErrAuthorizationPending
			}
			authorization := deviceResponseAuthorization(t, now)
			w := httptest.NewRecorder()
			writeDeviceAuthorization(w, r, projectAt, authorization, resultErr)
			assertDeviceResponse(t, w, 503, map[string]any{"error": "temporarily_unavailable"})
			if _, err := authorization.DeviceCode.Reveal(); err != nil {
				t.Fatal("unusable response consumed device custody")
			}
			poll := deviceResponsePollResult(t, now, true)
			w = httptest.NewRecorder()
			writeDevicePoll(w, r, projectAt, poll, resultErr)
			assertDeviceResponse(t, w, 503, map[string]any{"error": "temporarily_unavailable"})
			if _, err := poll.Tokens.AccessToken.Reveal(); err != nil {
				t.Fatal("unusable response consumed access custody")
			}
		})
	}
}

func TestDevicePollResponseMissingAccessCustodyDoesNotConsumeRefresh(t *testing.T) {
	now := time.Unix(1800000000, 0)
	out := deviceResponsePollResult(t, now, true)
	out.Tokens.AccessToken = oauth.Token{}
	w := httptest.NewRecorder()
	writeDevicePoll(w, httptest.NewRequest(http.MethodPost, "https://issuer.example/token", nil), now, out, nil)
	assertDeviceResponse(t, w, 503, map[string]any{"error": "temporarily_unavailable"})
	if _, err := out.Tokens.RefreshToken.Reveal(); err != nil {
		t.Fatal("missing access custody consumed selected refresh")
	}
}
