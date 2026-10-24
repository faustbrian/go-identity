package passkeyhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// The canonical route pair has one explicit, closed wire discriminator. This
// routing read authenticates nothing and never falls back after owner denial.
// Both branch pipelines repeat their own bounded admission against unchanged
// raw bytes. The outer budget includes this initial read as well as the branch.
type registrationDispatcher struct {
	enrollment, signup http.Handler
	decoder            *identityhttp.RequestDecoder
	operation          string
	maximum            time.Duration
}

func selectedRegistrationHandler(c FeatureConfig, m []identityhttp.MiddlewareDescriptor, complete bool) (http.Handler, error) {
	var enrollment, signup http.Handler
	var err error
	if c.Registration != nil {
		enrollment, err = newRegistrationHandler(*c.Registration, m, complete)
		if err != nil {
			return nil, err
		}
	}
	if c.Signup != nil {
		signup, err = newSignupHandler(*c.Signup, m, complete)
		if err != nil {
			return nil, err
		}
	}
	if enrollment == nil {
		return signup, nil
	}
	if signup == nil {
		return enrollment, nil
	}
	// One public route has one ingress profile and shared rate identities.
	// Host/proxy admission is still performed by the selected branch itself.
	a, b := c.Registration.Network, c.Signup.Network
	if a.Limits != b.Limits || a.MaximumForwardedHops != b.MaximumForwardedHops || !slices.Equal(a.TrustedProxyCIDRs, b.TrustedProxyCIDRs) || !slices.Equal(a.TenantHosts, b.TenantHosts) || !slices.Equal(a.PublicHosts, b.PublicHosts) || c.Registration.Origin != c.Signup.Origin || c.Registration.SessionCookie != c.Signup.SessionCookie || c.Registration.OptionsRate != c.Signup.OptionsRate || c.Registration.VerificationRate != c.Signup.VerificationRate {
		return nil, identityhttp.ErrInvalidInput
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Signup.Network.Limits)
	if err != nil {
		return nil, err
	}
	operation := "register-options"
	if complete {
		operation = "register-verify"
	}
	return &registrationDispatcher{enrollment: enrollment, signup: signup, decoder: decoder, operation: operation, maximum: min(c.Registration.MaximumDuration, c.Signup.MaximumDuration)}, nil
}

func (d *registrationDispatcher) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	enrollment, err := identityhttp.WithOperationMiddleware(d.enrollment, m)
	if err != nil {
		return nil, err
	}
	signup, err := identityhttp.WithOperationMiddleware(d.signup, m)
	if err != nil {
		return nil, err
	}
	copy := *d
	copy.enrollment, copy.signup = enrollment, signup
	return &copy, nil
}

func (d *registrationDispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/passkey/"+d.operation || r.URL.EscapedPath() != r.URL.Path {
		reject(w, r, failure{status: 404, code: "not_found"})
		return
	}
	if r.Method != http.MethodPost {
		reject(w, r, failure{status: 405, code: "method_not_allowed"})
		return
	}
	ctx, stop := context.WithTimeout(r.Context(), d.maximum)
	defer stop()
	request := r.Clone(ctx)
	// RawMessage omits surrounding JSON whitespace. Retain the exact bounded
	// bytes that were validated so the selected decoder can enforce the same
	// Content-Length/framing rather than silently rewriting request metadata.
	var original bytes.Buffer
	defer func() { clear(original.Bytes()) }()
	if request.Body != nil {
		request.Body = struct {
			io.Reader
			io.Closer
		}{io.TeeReader(request.Body, &original), request.Body}
	}
	wire, err := identityhttp.DecodeJSON[json.RawMessage](d.decoder, request)
	if err != nil {
		reject(w, r, identityhttp.ErrInvalidInput)
		return
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(wire, &fields) != nil {
		reject(w, r, identityhttp.ErrInvalidInput)
		return
	}
	body, err := decodeBody(d.operation, fields)
	if err != nil {
		reject(w, r, identityhttp.ErrInvalidInput)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(original.Bytes()))
	if body.signup {
		d.signup.ServeHTTP(w, request)
	} else {
		d.enrollment.ServeHTTP(w, request)
	}
}
