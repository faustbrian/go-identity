package mfahttp

import (
	identityhttp "github.com/faustbrian/go-identity/http"
	"net/http"
	"strings"
)

// This is a closed transport discriminator, not authentication fallback. The
// absent header retains the released login profile; only one exact enrollment
// value selects authenticated factor confirmation. Do not inspect/reparse body
// or infer a variant from ambient cookies, proof shape or failed authentication.
type verifyDispatch struct {
	login, password, enrollment, stepup http.Handler
	passwordDefault                     bool
}

func (h *verifyDispatch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var selected http.Handler
	valid := h != nil && r != nil
	if valid {
		present := false
		var values []string
		for name, value := range r.Header {
			if strings.EqualFold(name, "X-MFA-Variant") {
				if present {
					valid = false
					break
				}
				present = true
				values = value
			}
		}
		if valid {
			if !present {
				selected = h.login
				if h.passwordDefault {
					selected = h.password
				}
			} else if len(values) == 1 && values[0] == "enrollment" {
				selected = h.enrollment
			} else if len(values) == 1 && values[0] == "password" {
				selected = h.password
			} else if len(values) == 1 && values[0] == "step-up" {
				selected = h.stepup
			} else {
				valid = false
			}
		}
	}
	if !valid || selected == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		for name := range w.Header() {
			if strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "X-CSRF-Token") || strings.EqualFold(name, "X-MFA-Token") || strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Location") || strings.EqualFold(name, "Trailer") || strings.HasPrefix(name, http.TrailerPrefix) {
				delete(w.Header(), name)
			}
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("{\"error\":\"invalid_request\"}\n"))
		return
	}
	selected.ServeHTTP(w, r)
}

func (h *verifyDispatch) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if h == nil || h.login == nil && h.enrollment == nil && h.password == nil && h.stepup == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	out := &verifyDispatch{passwordDefault: h.passwordDefault}
	var err error
	if h.login != nil {
		out.login, err = identityhttp.WithOperationMiddleware(h.login, m)
		if err != nil {
			return nil, err
		}
	}
	if h.enrollment != nil {
		out.enrollment, err = identityhttp.WithOperationMiddleware(h.enrollment, m)
		if err != nil {
			return nil, err
		}
	}
	if h.password != nil {
		out.password, err = identityhttp.WithOperationMiddleware(h.password, m)
		if err != nil {
			return nil, err
		}
	}
	if h.stepup != nil {
		out.stepup, err = identityhttp.WithOperationMiddleware(h.stepup, m)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
