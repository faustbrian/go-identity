package onetap

import "fmt"

// BrowserRedirectStartRequest retains one bounded redirect-button intent for
// trusted native execution. It is deliberately distinct from BrowserStartRequest:
// neither assignment nor conversion may route a redirect through callback start.
// The zero value is invalid. Copies are immutable and safe for concurrent reads.
// Construction grants no origin authorization, risk, reservation or flow authority.
type BrowserRedirectStartRequest struct {
	// Wrapping the closure-backed original preserves its diagnostic redaction
	// even when fmt traverses this private field without invoking Format.
	request BrowserStartRequest
}

// NewBrowserRedirectStartRequest freezes only constructor-selected redirect
// button options and an explicitly resolved Remember policy. The trusted
// transport supplies the same exact bounded input shape as callback start;
// provider, client and registered login URI remain native configuration, not
// request fields. Prompt/popup selections, missing options or invalid context
// return an invalid request and redacted InvalidInput. No IO or entropy runs.
func NewBrowserRedirectStartRequest(spec BrowserStartRequestSpec) (BrowserRedirectStartRequest, error) {
	if !spec.Options.redirect {
		return BrowserRedirectStartRequest{}, failure(InvalidInput, nil)
	}
	original, err := newBrowserStartRequest(spec)
	if err != nil {
		return BrowserRedirectStartRequest{}, err
	}
	return BrowserRedirectStartRequest{request: original}, nil
}

// Bindings returns the exact original request for trusted native execution
// without renewing its retry key, option selection or resolved lifetime policy.
// The zero value returns an empty spec and redacted InvalidInput.
func (r BrowserRedirectStartRequest) Bindings() (BrowserStartRequestSpec, error) {
	return r.request.Bindings()
}

// Format redacts the original transport, retry and selected-option context.
func (BrowserRedirectStartRequest) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON denies accidental export of the validated original.
func (BrowserRedirectStartRequest) MarshalJSON() ([]byte, error) {
	return nil, failure(InvalidInput, nil)
}

// MarshalText denies accidental export of the validated original.
func (BrowserRedirectStartRequest) MarshalText() ([]byte, error) {
	return nil, failure(InvalidInput, nil)
}
