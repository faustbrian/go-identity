package identityhttp

import (
	"context"
	"net/http"
	"time"
)

// ReadinessCode identifies a blocking condition in a composed snapshot. Codes
// are opaque, non-secret ASCII labels of 1..128 bytes, not diagnostic messages.
// Public probe responses deliberately do not serialize these internal labels.
type ReadinessCode string

// ReadinessSnapshot is the composition owner's current dependency, migration
// and key decision. Ready requires no blocking Codes; not-ready requires 1..64
// Codes. Optional dependency degradation need not prevent Ready. Callbacks own
// the returned slice; it must remain unchanged until the check returns to its
// caller. The transport retains neither it nor its values after the request.
type ReadinessSnapshot struct {
	Ready bool
	Codes []ReadinessCode
}

// ReadinessCheckFunc must be safe for concurrent calls, honor cancellation and
// complete within its context deadline. It runs synchronously, without lifecycle
// locks or transport retries. The transport cannot terminate arbitrary callback
// code that ignores cancellation and does not detach it in another goroutine.
type ReadinessCheckFunc func(context.Context) (ReadinessSnapshot, error)

// ReadinessProvider supplies the selected composition's real readiness check.
// The zero value is invalid. A healthy listener alone is not a valid check.
type ReadinessProvider struct{ Check ReadinessCheckFunc }

// ServerStateFunc returns the current lifecycle state. Supply HTTPServer.State
// in composition; the function must be concurrent-safe, prompt and perform no IO.
// It is called before and after readiness work, never under a transport lock.
type ServerStateFunc func() ServerState

// ProbeConfig is copied at construction. State and Readiness.Check are required;
// Timeout must be positive and at most two seconds. An earlier request deadline
// always wins. Construction performs no checks, IO or global route registration.
type ProbeConfig struct {
	State     ServerStateFunc
	Readiness ReadinessProvider
	Timeout   time.Duration
}

// NewProbeHandlers returns separate immutable liveness and readiness handlers.
// Their only accepted requests are exact GET /healthz and GET /readyz,
// respectively; HEAD is not implicitly enabled. Query strings, escaped aliases,
// nonempty/framed bodies and Idempotency-Key are rejected. Routing mismatches
// are 404, methods are 405 with Allow: GET, malformed empty requests are 400.
// Responses are fixed application/json with Cache-Control: no-store and nosniff.
// Liveness emits {"status":"alive"}; readiness emits only {"ready":true/false},
// never callback codes or errors. Readiness is 200 only while Running with a
// valid affirmative snapshot and a live check context; every other result is
// 503. A final state check denies callbacks finishing during drain. Like every
// instantaneous probe, success describes its final observation, not a lease.
//
// The returned handlers support OperationMiddlewareBinder. Bound hooks observe
// explicit public/no-auth stages after input validation, with Authorization,
// proxy credentials and cookies removed from detached request views. They
// receive no principal. Their response writer discards output: short circuits
// deny with fixed503 rather than invent readiness; only the probe owns output.
// Original unbound handlers remain unchanged. Bound hooks share a whole-call
// budget of max(Timeout,1ms); readiness retains its original narrower bound.
// Rebinding appends hooks without changing owners; cancellation and final drain
// are checked again after hook unwind. No response or readiness is cached.
//
// Register these handlers at their exact paths on a private mux before serving.
// They do not register domain routes or implement the full transport rate policy,
// direct operation API, endpoint manifest or OpenAPI contract. A draining/closed
// HTTPServer can refuse network admission independently of handler liveness.
func NewProbeHandlers(config ProbeConfig) (liveness, readiness http.Handler, err error) {
	if config.State == nil || config.Readiness.Check == nil || config.Timeout <= 0 || config.Timeout > 2*time.Second {
		return nil, nil, ErrInvalidInput
	}
	liveness = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !probeRequest(w, r, "/healthz") {
			return
		}
		probeResponse(w, http.StatusOK, "{\"status\":\"alive\"}\n")
	})
	readiness = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !probeRequest(w, r, "/readyz") {
			return
		}
		if config.State() != ServerRunning || r.Context().Err() != nil {
			probeResponse(w, http.StatusServiceUnavailable, "{\"ready\":false}\n")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), config.Timeout)
		defer cancel()
		snapshot, err := config.Readiness.Check(ctx)
		if err == nil && snapshot.Ready && len(snapshot.Codes) == 0 && config.State() == ServerRunning && ctx.Err() == nil {
			probeResponse(w, http.StatusOK, "{\"ready\":true}\n")
			return
		}
		probeResponse(w, http.StatusServiceUnavailable, "{\"ready\":false}\n")
	})
	liveness = &probeHandler{handler: liveness, config: config, path: "/healthz"}
	readiness = &probeHandler{handler: readiness, config: config, path: "/readyz"}
	return liveness, readiness, nil
}

func probeRequest(w http.ResponseWriter, r *http.Request, path string) bool {
	if r == nil || r.URL == nil {
		probeResponse(w, http.StatusBadRequest, "{\"error\":\"invalid_request\"}\n")
		return false
	}
	if r.URL.Path != path || r.URL.EscapedPath() != path {
		probeResponse(w, http.StatusNotFound, "{\"error\":\"not_found\"}\n")
		return false
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		body := "{\"error\":\"method_not_allowed\"}\n"
		if r.Method == http.MethodHead {
			body = ""
		}
		probeResponse(w, http.StatusMethodNotAllowed, body)
		return false
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || (r.Body != nil && r.Body != http.NoBody) || len(r.Trailer) != 0 || len(r.Header.Values("Idempotency-Key")) != 0 {
		probeResponse(w, http.StatusBadRequest, "{\"error\":\"invalid_request\"}\n")
		return false
	}
	return true
}

func probeResponse(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	w.Write([]byte(body))
}
