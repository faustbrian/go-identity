package oauthserverhttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/faustbrian/go-oauth-server/device"
)

// DeviceConsentConfig selects the browser-cookie device review profile. Service
// must be the configured native device owner with its actual recent human
// session and transactional CSRF dependencies; syntactic cookie acquisition is
// not authentication. Origin must equal its configured HTTPS issuer origin.
// Network and cookie policy are frozen at construction; the concurrent service
// and prompt clock are borrowed for the handlers' lifetime. MaximumDuration is
// 1ms..30s and never extends an earlier deadline. No goroutines or resources are
// created and no session, consent, authorization or recovery owner is replaced.
type DeviceConsentConfig struct {
	Service         *device.Service
	Network         identityhttp.NetworkConfig
	SessionCookie   session.CookiePolicy
	Origin          identityhttp.Origin
	Now             func() time.Time
	MaximumDuration time.Duration
}

func (DeviceConsentConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oauthserverhttp.DeviceConsentConfig(redacted)"))
}

// MarshalJSON denies accidental export of borrowed owners and policy.
func (DeviceConsentConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText denies accidental export of borrowed owners and policy.
func (DeviceConsentConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

type deviceConsentInput struct {
	verification device.Verification
	csrf         session.CSRFToken
	confirmed    string
}

func (deviceConsentInput) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oauthserverhttp.deviceConsentInput(redacted)"))
}
func (deviceConsentInput) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (deviceConsentInput) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

func newDeviceConsentHandler(c DeviceConsentConfig, operation string) (http.Handler, error) {
	method := http.MethodPost
	switch operation {
	case "device-inspect":
		method = http.MethodGet
	case "device-approve", "device-deny":
	default:
		return nil, identityhttp.ErrInvalidInput
	}
	if !c.Service.Enabled() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || c.Network.Limits.MaximumBodyBytes > 16384 || c.Network.Limits.MaximumDecodedBytes > 16384 {
		return nil, identityhttp.ErrInvalidInput
	}
	endpoint, err := url.Parse(c.Service.Metadata().DeviceAuthorizationEndpoint)
	if err != nil || endpoint.Scheme+"://"+endpoint.Host != string(c.Origin) {
		return nil, identityhttp.ErrInvalidInput
	}
	cookie, err := c.SessionCookie.DeletionAttributes()
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return nil, err
	}
	origins, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{c.Origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origins, FormField: "csrf_token"})
	if err != nil {
		return nil, err
	}
	return identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[deviceConsentInput]{MaximumDuration: c.MaximumDuration,
		Decode: func(r *http.Request) (deviceConsentInput, error) {
			var in deviceConsentInput
			invalid := protocolFailure{status: 400, code: "invalid_request"}
			if r == nil || r.URL == nil || r.URL.Path != "/v1/oauth-server/"+operation || r.URL.RawPath != "" {
				return in, protocolFailure{status: 404, code: "invalid_request"}
			}
			if r.Method != method {
				return in, protocolFailure{status: 405, code: "invalid_request"}
			}
			if r.URL.ForceQuery || r.URL.User != nil || r.URL.Fragment != "" || len(r.Trailer) != 0 || len(r.TransferEncoding) != 0 {
				return in, invalid
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return in, invalid
			}
			facts, err := network.Resolve(r)
			if err != nil || facts.Scheme() != "https" || facts.Origin() != string(c.Origin) {
				return in, protocolFailure{status: 421, code: "invalid_request"}
			}
			bearer, _, err := decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderRequired)
			if err != nil {
				return in, invalid
			}
			var fields url.Values
			if operation == "device-inspect" {
				if r.ContentLength != 0 || r.Body != nil && r.Body != http.NoBody {
					return in, invalid
				}
				for name := range r.Header {
					if strings.EqualFold(name, "Content-Type") || strings.EqualFold(name, "X-CSRF-Token") {
						return in, invalid
					}
				}
				fields, err = decoder.Query(r)
			} else {
				if r.URL.RawQuery != "" {
					return in, invalid
				}
				in.csrf, fields, err = identityhttp.DecodeCSRF(csrf, r, session.ParseCSRFToken)
				if err != nil {
					return in, protocolFailure{status: 403, code: "origin_or_csrf_denied"}
				}
				if fields == nil {
					fields, err = deviceConsentJSON(decoder, r)
				}
			}
			if err != nil {
				return in, invalid
			}
			expected := 1
			if operation == "device-approve" {
				expected = 2
				confirmed, err := device.ParseUserCode(fields.Get("confirmed_user_code"))
				if err != nil {
					return in, invalid
				}
				in.confirmed = string(confirmed)
			}
			if len(fields) != expected {
				return in, invalid
			}
			code, err := device.ParseUserCode(fields.Get("user_code"))
			if err != nil {
				return in, invalid
			}
			in.verification = device.Verification{Session: bearer, UserCode: string(code), Network: facts.ClientIP().String()}
			return in, nil
		},
		// The sole native call below authenticates the real current session and
		// admits its rate/current-authority/transactional CSRF fences together.
		// A preliminary second read cannot replace that native authority.
		Authenticate: func(_ *http.Request, in deviceConsentInput) (deviceConsentInput, error) { return in, nil },
		Admit:        func(r *http.Request, _ deviceConsentInput) error { return r.Context().Err() },
		Handle: func(w http.ResponseWriter, r *http.Request, in deviceConsentInput) {
			switch operation {
			case "device-inspect":
				out, err := c.Service.Inspect(r.Context(), in.verification)
				writeDevicePrompt(w, r, c.Now(), out, err)
			case "device-approve":
				out, err := c.Service.Approve(r.Context(), device.Approval{Verification: in.verification, CSRF: in.csrf, Origin: string(c.Origin), ConfirmedUserCode: in.confirmed})
				writeDeviceConsentCompletion(w, r, operation, out, err)
			case "device-deny":
				out, err := c.Service.Deny(r.Context(), device.Denial{Verification: in.verification, CSRF: in.csrf, Origin: string(c.Origin)})
				writeDeviceConsentCompletion(w, r, operation, out, err)
			}
		}, Reject: func(w http.ResponseWriter, r *http.Request, err error) {
			if f := protocolError(err); f.status == 405 {
				w.Header().Set("Allow", method)
				writeJSON(w, f.status, struct {
					Error string `json:"error"`
				}{f.code})
				return
			}
			rejectDevice(w, r, err)
		}})
}

func deviceConsentJSON(decoder *identityhttp.RequestDecoder, r *http.Request) (url.Values, error) {
	body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
	if err != nil {
		return nil, err
	}
	fields := make(url.Values, len(body))
	for name, raw := range body {
		if name != "user_code" && name != "confirmed_user_code" {
			return nil, identityhttp.ErrInvalidInput
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, identityhttp.ErrInvalidInput
		}
		fields[name] = []string{value}
	}
	return fields, nil
}

func writeDevicePrompt(w http.ResponseWriter, r *http.Request, now time.Time, out oauth.DevicePrompt, err error) {
	if r.Context().Err() != nil || now.IsZero() {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	if err != nil {
		rejectDevice(w, r, err)
		return
	}
	code, codeErr := device.ParseUserCode(out.UserCode)
	_, scopesErr := oauth.NewScopeCatalog(out.Scopes)
	if codeErr != nil || string(code) != out.UserCode || !devicePromptText(out.ClientDisplay, 128) || !devicePromptText(out.Resource, 2048) || scopesErr != nil || !now.Before(out.ExpiresAt) {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	writeJSON(w, 200, struct {
		CanonicalUserCode string    `json:"canonical_user_code"`
		ClientDisplayName string    `json:"client_display_name"`
		Scopes            []string  `json:"scopes"`
		Resources         []string  `json:"resources"`
		ExpiresAt         time.Time `json:"expires_at"`
	}{out.UserCode, out.ClientDisplay, out.Scopes, []string{out.Resource}, out.ExpiresAt})
}

func devicePromptText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

type deviceConsentCompletionWire struct {
	Outcome   string             `json:"outcome"`
	CommandID identity.CommandID `json:"command_id,omitempty"`
	Replayed  bool               `json:"replayed"`
}

func writeDeviceConsentCompletion(w http.ResponseWriter, r *http.Request, operation string, completion oauth.Completion, err error) {
	if r.Context().Err() != nil {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	if err != nil {
		rejectDevice(w, r, err)
		return
	}
	if completion.Outcome != identity.CommitOutcomeCommitted || operation == "device-approve" && completion.Replayed {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	state := "approved"
	if operation == "device-deny" {
		state = "denied"
	} else if operation != "device-approve" {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	command := completion.CommandID
	if completion.Replayed {
		// An already-denied request has no new command and must not disclose
		// the original reviewer's command, even if native metadata contains it.
		command = ""
	} else if _, err := identity.ParseCommandID(string(command)); err != nil {
		reject(w, r, oauth.ErrUnavailable)
		return
	}
	writeJSON(w, 200, struct {
		State      string                      `json:"state"`
		Completion deviceConsentCompletionWire `json:"completion"`
	}{state, deviceConsentCompletionWire{"committed", command, completion.Replayed}})
}
