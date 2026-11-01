package oauthserverhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	oauth "github.com/faustbrian/go-oauth-server"
)

type protocolInput struct {
	facts      identityhttp.NetworkFacts
	client     string
	credential oauth.ClientAuthentication
	token      oauth.TokenRequest
	inspect    oauth.IntrospectRequest
	revoke     oauth.RevokeRequest
}

func (*protocolInput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "oauthserverhttp.input(redacted)")
}

type protocolFailure struct {
	status int
	code   string
	retry  time.Duration
}

func (f protocolFailure) Error() string { return "oauthserverhttp: " + f.code }

func protocolError(err error) protocolFailure {
	var f protocolFailure
	if errors.As(err, &f) {
		return f
	}
	switch {
	case errors.Is(err, oauth.ErrInvalidClient):
		return protocolFailure{status: 401, code: "invalid_client"}
	case errors.Is(err, oauth.ErrUnsupportedGrant):
		return protocolFailure{status: 400, code: "unsupported_grant_type"}
	case errors.Is(err, oauth.ErrInvalidScope):
		return protocolFailure{status: 400, code: "invalid_scope"}
	case errors.Is(err, oauth.ErrInvalidGrant), errors.Is(err, oauth.ErrAccessDenied):
		return protocolFailure{status: 400, code: "invalid_grant"}
	case errors.Is(err, oauth.ErrInvalidRequest), errors.Is(err, identityhttp.ErrInvalidInput):
		return protocolFailure{status: 400, code: "invalid_request"}
	default:
		return protocolFailure{status: 503, code: "temporarily_unavailable"}
	}
}

func rateFailure(retry time.Duration, err error) error {
	if errors.Is(err, identityhttp.ErrRateLimited) {
		return protocolFailure{status: 429, code: "temporarily_unavailable", retry: retry}
	}
	return protocolFailure{status: 503, code: "temporarily_unavailable"}
}

func reject(w http.ResponseWriter, _ *http.Request, err error) {
	f := protocolError(err)
	if f.status == 401 {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth2"`)
	}
	if f.status == 405 {
		w.Header().Set("Allow", "POST")
	}
	if f.retry > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(int64((min(max(f.retry, time.Second), time.Hour)+time.Second-1)/time.Second), 10))
	}
	writeJSON(w, f.status, struct {
		Error string `json:"error"`
	}{f.code})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil || len(body) > 16384 {
		status, body = 503, []byte(`{"error":"temporarily_unavailable"}`)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func newHandler(c FeatureConfig, action, issuer string, network *identityhttp.NetworkResolver, decoder *identityhttp.RequestDecoder, rate *protocolRate) (http.Handler, error) {
	return identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[*protocolInput]{MaximumDuration: c.MaximumDuration,
		Decode: func(r *http.Request) (*protocolInput, error) {
			if r == nil || r.URL == nil || r.URL.Path != "/oauth2/"+action || r.URL.RawPath != "" {
				return nil, protocolFailure{status: 404, code: "invalid_request"}
			}
			if r.Method != "POST" {
				return nil, protocolFailure{status: 405, code: "invalid_request"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.User != nil || r.URL.Fragment != "" || len(r.Trailer) != 0 {
				return nil, oauth.ErrInvalidRequest
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return nil, oauth.ErrInvalidRequest
			}
			facts, err := network.Resolve(r)
			if err != nil || facts.Scheme() != "https" || facts.Origin() != issuer {
				return nil, protocolFailure{status: 421, code: "invalid_request"}
			}
			if retry, err := rate.admitIP(r.Context(), facts, action); err != nil {
				return nil, rateFailure(retry, err)
			}
			fields, err := decoder.Form(r)
			if err != nil {
				return nil, oauth.ErrInvalidRequest
			}
			var headers []string
			for name, values := range r.Header {
				if strings.EqualFold(name, "Proxy-Authorization") {
					return nil, oauth.ErrInvalidRequest
				}
				if strings.EqualFold(name, "Authorization") {
					headers = append(headers, values...)
				}
			}
			if len(headers) != 1 {
				return nil, oauth.ErrInvalidClient
			}
			in := &protocolInput{facts: facts}
			raw := fields.Encode()
			switch action {
			case "token":
				in.token, err = oauth.ParseTokenFormWithClientAuthentication(raw, headers)
				if err == nil && in.token.GrantType != oauth.ClientCredentialsGrant {
					return nil, oauth.ErrUnsupportedGrant
				}
				in.client, in.credential, in.token.Network = in.token.ClientID, in.token.ClientAuthentication, facts.ClientIP().String()
			case "introspect":
				in.inspect, err = oauth.ParseIntrospectionForm(raw, headers)
				in.client, in.credential = in.inspect.ClientID, in.inspect.ClientAuthentication
			case "revoke":
				in.revoke, err = oauth.ParseRevocationForm(raw, headers)
				in.client, in.credential, in.revoke.Network = in.revoke.ClientID, in.revoke.ClientAuthentication, facts.ClientIP().String()
			default:
				return nil, oauth.ErrInvalidRequest
			}
			if err != nil {
				return nil, err
			}
			if in.credential.Method() != "client_secret_basic" {
				return nil, oauth.ErrInvalidClient
			}
			return in, nil
		},
		Authenticate: func(r *http.Request, in *protocolInput) (*protocolInput, error) {
			if err := c.Service.AuthenticateClient(r.Context(), in.client, in.credential); err != nil {
				if errors.Is(err, oauth.ErrInvalidRequest) || errors.Is(err, oauth.ErrAccessDenied) {
					err = oauth.ErrInvalidClient
				}
				return nil, err
			}
			return in, nil
		},
		Admit: func(r *http.Request, in *protocolInput) error {
			retry, err := rate.admitClient(r.Context(), in.facts, action, in.client)
			if err != nil {
				return rateFailure(retry, err)
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, in *protocolInput) {
			switch action {
			case "token":
				out, err := c.Service.Token(r.Context(), in.token)
				if err != nil {
					reject(w, r, err)
					return
				}
				now := c.Now()
				if r.Context().Err() != nil || now.IsZero() || out.Outcome != identity.CommitOutcomeCommitted || out.Replayed || !now.Before(out.ExpiresAt) || out.RefreshToken != (oauth.Token{}) || out.IDToken != (oauth.IDToken{}) || out.IssuedTokenType != "" {
					reject(w, r, oauth.ErrUnavailable)
					return
				}
				wire, err := out.AccessToken.Reveal()
				if err != nil {
					reject(w, r, oauth.ErrUnavailable)
					return
				}
				writeJSON(w, 200, struct {
					AccessToken string `json:"access_token"`
					TokenType   string `json:"token_type"`
					ExpiresIn   int64  `json:"expires_in"`
					Scope       string `json:"scope"`
				}{wire, "Bearer", int64(out.ExpiresAt.Sub(now) / time.Second), strings.Join(out.Scopes, " ")})
			case "introspect":
				out, err := c.Service.Introspect(r.Context(), in.inspect)
				if err != nil || r.Context().Err() != nil {
					if err == nil {
						err = oauth.ErrUnavailable
					}
					reject(w, r, err)
					return
				}
				writeJSON(w, 200, out)
			case "revoke":
				out, err := c.Service.Revoke(r.Context(), in.revoke)
				if err != nil || r.Context().Err() != nil || out.Outcome != identity.CommitOutcomeCommitted {
					if err == nil {
						err = oauth.ErrUnavailable
					}
					reject(w, r, err)
					return
				}
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Pragma", "no-cache")
				w.WriteHeader(200)
			}
		}, Reject: reject})
}
