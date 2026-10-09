package identityhttp

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Probe hooks observe public execution, not authentication. Their writer is a
// sink: only the owned probe may produce the fixed public response. Otherwise
// a short-circuiting hook could manufacture healthy readiness without a check.
type probeHandler struct {
	handler  http.Handler
	pipeline http.Handler
	config   ProbeConfig
	path     string
}

type probeRunKey struct{}
type probeRun struct {
	reply probeReply
}

type probeReply struct {
	status int
	body   string
	allow  string
}

func (probeReply) Error() string { return "identityhttp: probe rejected" }

type probeSink struct{ header http.Header }

func (w probeSink) Header() http.Header       { return w.header }
func (probeSink) WriteHeader(int)             {}
func (probeSink) Write(p []byte) (int, error) { return len(p), nil }

// The only writer of this capture is the fixed owned probe, never middleware.
type probeCapture struct {
	header http.Header
	status int
	body   strings.Builder
}

func (w *probeCapture) Header() http.Header { return w.header }
func (w *probeCapture) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *probeCapture) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}

func (h *probeHandler) budget() time.Duration {
	// Retain the existing 1ns..2s readiness bound. The generic hook pipeline's
	// minimum is 1ms; readiness still derives its own original narrower timeout.
	return max(h.config.Timeout, time.Millisecond)
}

func (h *probeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.pipeline == nil || r == nil || r.URL == nil {
		h.handler.ServeHTTP(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.budget())
	defer cancel()
	run := &probeRun{reply: h.unavailable()}
	owned := r.Clone(context.WithValue(ctx, probeRunKey{}, run))
	// Public probes neither consume nor disclose ambient credential channels.
	// Leave the caller's request untouched, including noncanonical header keys.
	for name := range owned.Header {
		if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization") || strings.EqualFold(name, "Cookie") || strings.EqualFold(name, "Cookie2") {
			delete(owned.Header, name)
		}
	}
	emitting := false
	defer func() {
		if p := recover(); p != nil {
			if emitting {
				panic(http.ErrAbortHandler)
			}
			// Pipeline commitment to the hook sink is not real HTTP commitment.
			// Before owned emission, even its redacted abort sentinel is a fixed
			// denial. Once real emission starts, preserve transport abort safety.
			h.write(w, r, h.unavailable())
		}
	}()
	h.pipeline.ServeHTTP(probeSink{header: make(http.Header)}, owned)
	if (h.path == "/readyz" && run.reply.status == 200 && h.config.State() != ServerRunning) || ctx.Err() != nil {
		run.reply = h.unavailable()
	}
	emitting = true
	h.write(w, r, run.reply)
}

func (h *probeHandler) unavailable() probeReply {
	if h.path == "/readyz" {
		return probeReply{status: 503, body: "{\"ready\":false}\n"}
	}
	return probeReply{status: 503, body: "{\"error\":\"unavailable\"}\n"}
}

func (h *probeHandler) write(w http.ResponseWriter, r *http.Request, reply probeReply) {
	if reply.allow != "" {
		w.Header().Set("Allow", reply.allow)
	}
	if r.Method == http.MethodHead {
		reply.body = ""
	}
	probeResponse(w, reply.status, reply.body)
}

func (h *probeHandler) WithOperationMiddleware(middleware []MiddlewareDescriptor) (http.Handler, error) {
	if h == nil || h.handler == nil {
		return nil, ErrInvalidInput
	}
	bound := &probeHandler{handler: h.handler, config: h.config, path: h.path}
	if h.pipeline != nil {
		// Existing callbacks retain the same immutable probe policy and owners.
		pipeline, err := WithOperationMiddleware(h.pipeline, middleware)
		if err != nil {
			return nil, err
		}
		bound.pipeline = pipeline
		return bound, nil
	}
	setReply := func(r *http.Request, reply probeReply) {
		if run, ok := r.Context().Value(probeRunKey{}).(*probeRun); ok {
			run.reply = reply
		}
	}
	pipeline, err := NewOperationPipeline(OperationPipelineConfig[struct{}]{
		MaximumDuration: bound.budget(), Middleware: middleware,
		Decode: func(r *http.Request) (struct{}, error) {
			capture := &probeCapture{header: make(http.Header)}
			if !probeRequest(capture, r, bound.path) {
				return struct{}{}, probeReply{status: capture.status, body: capture.body.String(), allow: capture.header.Get("Allow")}
			}
			return struct{}{}, nil
		},
		Authenticate: func(_ *http.Request, state struct{}) (struct{}, error) { return state, nil },
		Admit:        func(*http.Request, struct{}) error { return nil },
		Handle: func(_ http.ResponseWriter, r *http.Request, _ struct{}) {
			capture := &probeCapture{header: make(http.Header)}
			bound.handler.ServeHTTP(capture, r)
			setReply(r, probeReply{status: capture.status, body: capture.body.String(), allow: capture.header.Get("Allow")})
		},
		Reject: func(_ http.ResponseWriter, r *http.Request, err error) {
			reply := bound.unavailable()
			var malformed probeReply
			if errors.As(err, &malformed) {
				reply = malformed
			}
			setReply(r, reply)
		},
	})
	if err != nil {
		return nil, err
	}
	bound.pipeline = pipeline
	return bound, nil
}
