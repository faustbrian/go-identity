package oauthserverhttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/faustbrian/go-oauth-server/device"
)

func rejectDevice(w http.ResponseWriter, r *http.Request, err error) {
	for _, condition := range []device.Error{
		device.ErrInvalidRequest, device.ErrAuthorizationPending, device.ErrSlowDown,
		device.ErrAccessDenied, device.ErrExpiredToken,
	} {
		if errors.Is(err, condition) {
			reject(w, r, protocolFailure{status: 400, code: string(condition)})
			return
		}
	}
	reject(w, r, err)
}

func freshDeviceCompletion(completion oauth.Completion) bool {
	return completion.Outcome == identity.CommitOutcomeCommitted && completion.CommandID != "" && !completion.Replayed
}

func writeDeviceAuthorization(w http.ResponseWriter, r *http.Request, now time.Time, out device.Authorization, err error) {
	if r == nil || r.Context().Err() != nil || now.IsZero() {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	if err != nil {
		rejectDevice(w, r, err)
		return
	}
	if !freshDeviceCompletion(out.Completion) || !now.Before(out.ExpiresAt) || out.DeviceCode == (oauth.Token{}) {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	// The selected device PollPolicy projects integral 5..60 second intervals;
	// HTTP reports that native value without creating a polling policy of its own.
	if out.Interval < 5*time.Second || out.Interval > 60*time.Second || out.Interval%time.Second != 0 {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	if out.UserCode == "" || len(out.UserCode) > 128 || out.VerificationURI == "" || len(out.VerificationURI) > 2048 || out.VerificationURIComplete == "" || len(out.VerificationURIComplete) > 2048 {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	response := struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int64  `json:"expires_in"`
		Interval                int64  `json:"interval"`
	}{
		UserCode: out.UserCode, VerificationURI: out.VerificationURI,
		VerificationURIComplete: out.VerificationURIComplete,
		ExpiresIn:               int64(out.ExpiresAt.Sub(now) / time.Second), Interval: int64(out.Interval / time.Second),
	}
	// Check writeJSON's encoded-body ceiling before consuming custody. The
	// canonical device bearer adds exactly 43 unescaped JSON bytes (Token).
	body, encodeErr := json.Marshal(response)
	if encodeErr != nil || len(body) > 16384-43 {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	if r.Context().Err() != nil {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	response.DeviceCode, err = out.DeviceCode.Reveal()
	if err != nil {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	if r.Context().Err() != nil {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	writeJSON(w, 200, response)
}

func writeDevicePoll(w http.ResponseWriter, r *http.Request, now time.Time, out device.PollResult, err error) {
	if r == nil || r.Context().Err() != nil || now.IsZero() {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	if err != nil {
		rejectDevice(w, r, err)
		return
	}
	tokens := out.Tokens
	if !freshDeviceCompletion(out.Completion) || tokens.Outcome != identity.CommitOutcomeCommitted || tokens.Replayed || tokens.CommandID != out.Completion.CommandID || !now.Before(tokens.ExpiresAt) {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	if tokens.AccessToken == (oauth.Token{}) || tokens.IDToken != (oauth.IDToken{}) || tokens.IssuedTokenType != "" {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	if _, err := oauth.NewScopeCatalog(tokens.Scopes); err != nil {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	response := struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		RefreshToken string `json:"refresh_token,omitempty"`
	}{TokenType: "Bearer", ExpiresIn: int64(tokens.ExpiresAt.Sub(now) / time.Second), Scope: strings.Join(tokens.Scopes, " ")}
	if r.Context().Err() != nil {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	response.AccessToken, err = tokens.AccessToken.Reveal()
	if err != nil {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	if tokens.RefreshToken != (oauth.Token{}) {
		response.RefreshToken, err = tokens.RefreshToken.Reveal()
		if err != nil {
			reject(w, r, oauth.ErrUnavailable)
			return
		}
	}
	if r.Context().Err() != nil {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	writeJSON(w, 200, response)
}
