package oauthserverhttp

import (
	"net/http"
	"strings"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/faustbrian/go-oauth-server/device"
)

// newDeviceAuthorizationHandler borrows the completely selected native device
// service and existing HTTP owners. Registration, discovery and token-grant
// selection remain composition responsibilities. It owns neither resources nor
// a second client-authentication or device-issuance implementation.
func newDeviceAuthorizationHandler(service *device.Service, now func() time.Time, duration time.Duration, issuer string, network *identityhttp.NetworkResolver, decoder *identityhttp.RequestDecoder, rate *protocolRate) (http.Handler, error) {
	if !service.Enabled() || now == nil || duration < time.Millisecond || duration > 30*time.Second || network == nil || decoder == nil || rate == nil || rate.service == nil || rate.issuer != issuer {
		return nil, identityhttp.ErrInvalidInput
	}
	if _, err := oauth.NewIssuer(issuer); err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	metadata := service.Metadata()
	if metadata.DeviceAuthorizationEndpoint != issuer+"/oauth2/device_authorization" || metadata.TokenEndpoint != issuer+"/oauth2/token" || metadata.GrantType != device.GrantType {
		return nil, identityhttp.ErrInvalidInput
	}
	return identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[device.DeviceRequest]{MaximumDuration: duration,
		Decode: func(r *http.Request) (device.DeviceRequest, error) {
			var zero device.DeviceRequest
			if r == nil || r.URL == nil || r.URL.Path != "/oauth2/device_authorization" || r.URL.RawPath != "" {
				return zero, protocolFailure{status: 404, code: "invalid_request"}
			}
			if r.Method != http.MethodPost {
				return zero, protocolFailure{status: 405, code: "invalid_request"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.User != nil || r.URL.Fragment != "" || len(r.Trailer) != 0 {
				return zero, device.ErrInvalidRequest
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return zero, device.ErrInvalidRequest
			}
			facts, err := network.Resolve(r)
			if err != nil || facts.Scheme() != "https" || facts.Origin() != issuer {
				return zero, protocolFailure{status: 421, code: "invalid_request"}
			}
			// The catalog's rate.protocol IP policy applies before parsing or
			// client admission. Its distinct key kind prevents device issuance
			// from consuming workload-token or introspection/revocation budgets.
			if retry, err := rate.admit(r.Context(), rate.protocolIP, "device-authorization-ip", facts.ClientIP().String()); err != nil {
				return zero, rateFailure(retry, err)
			}
			var authorization []string
			for name, values := range r.Header {
				if strings.EqualFold(name, "Proxy-Authorization") {
					return zero, device.ErrInvalidRequest
				}
				if strings.EqualFold(name, "Authorization") {
					authorization = append(authorization, values...)
				}
			}
			fields, err := decoder.Form(r)
			if err != nil {
				return zero, device.ErrInvalidRequest
			}
			in, err := device.ParseDeviceRequest(fields.Encode(), authorization)
			if err != nil {
				return zero, err
			}
			in.Network = facts.ClientIP().String()
			return in, nil
		},
		// Service.Authorize performs real public-none/Basic authentication and
		// native current-client admission before generating or storing codes.
		Authenticate: func(_ *http.Request, in device.DeviceRequest) (device.DeviceRequest, error) { return in, nil },
		Admit:        func(r *http.Request, _ device.DeviceRequest) error { return r.Context().Err() },
		Handle: func(w http.ResponseWriter, r *http.Request, in device.DeviceRequest) {
			out, err := service.Authorize(r.Context(), in)
			writeDeviceAuthorization(w, r, now(), out, err)
		}, Reject: rejectDevice})
}
