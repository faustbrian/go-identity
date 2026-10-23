package passkeyhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
)

type failure struct {
	status    int
	code      string
	retry     time.Duration
	allow     string
	commandID identity.CommandID
	outcome   string
}

// optionsResponse never implicitly serializes an opaque options value: Options
// is populated only within its successful explicit native TransferJSON call.
type optionsResponse struct {
	CommandID     identity.CommandID `json:"commandID"`
	CommitOutcome string             `json:"commitOutcome"`
	Replayed      bool               `json:"replayed"`
	Options       json.RawMessage    `json:"options,omitempty"`
}

func (f failure) Error() string { return "passkeyhttp: " + f.code }

func domainFailure(err error) error {
	var denied identity.ForbiddenError
	var invalid identity.InvalidInputError
	var conflict identity.ConflictError
	var busy identity.InProgressError
	var unknown identity.UnknownCommitError
	var aborted identity.NotCommittedError
	switch {
	case errors.As(err, &unknown):
		return commandFailure(failure{status: 503, code: "unknown", commandID: unknown.CommandID, outcome: "unknown"})
	case errors.As(err, &aborted):
		return commandFailure(failure{status: 503, code: "not_committed", commandID: aborted.CommandID, outcome: "not_committed"})
	case errors.As(err, &denied):
		return failure{status: 403, code: "denied"}
	case errors.As(err, &invalid), errors.Is(err, identityhttp.ErrInvalidInput):
		return failure{status: 400, code: "invalid_request"}
	case errors.As(err, &conflict):
		return commandFailure(failure{status: 409, code: "conflict", commandID: conflict.CommandID, outcome: "conflict"})
	case errors.As(err, &busy):
		return commandFailure(failure{status: 409, code: "in_progress", retry: busy.RetryAfter, commandID: busy.CommandID, outcome: "in_progress"})
	default:
		return identityhttp.ErrUnavailable
	}
}

// Only the native owner's typed observation supplies recovery identity. A
// browser command locator alone never establishes admission or commitment.
func commandFailure(f failure) error {
	if f.commandID == "" && f.outcome == "conflict" {
		return f
	}
	if _, err := identity.ParseCommandID(string(f.commandID)); err != nil {
		return identityhttp.ErrUnavailable
	}
	return f
}

// Native observations are captured only at the actual owner call sites, never
// by inspecting response bytes or accepting middleware-created error state.
// They describe past durability, not current authorization or delivery validity.
func rejectNative(w http.ResponseWriter, r *http.Request, err error) {
	mapped := domainFailure(err)
	var f failure
	if errors.As(mapped, &f) && f.commandID != "" && f.outcome != "" {
		requestDelivery(r).observed = &f
	}
	reject(w, r, mapped)
}

// Call only after the owner receipt/opaque completion bindings are validated.
// A later timeout cannot turn an acknowledged commitment into an unknown abort.
func (d *delivery) observeCommitted(commandID identity.CommandID) {
	if _, err := identity.ParseCommandID(string(commandID)); err == nil {
		d.observed = &failure{status: 503, code: "unavailable", commandID: commandID, outcome: "committed"}
	}
}

func rateFailure(result identityhttp.AuthRateResult, err error) error {
	if errors.Is(err, identityhttp.ErrRateLimited) {
		return failure{status: 429, code: "rate_limited", retry: result.RetryAfter}
	}
	if errors.Is(err, identityhttp.ErrRateUnavailable) {
		return failure{status: 503, code: "rate_limiter_unavailable"}
	}
	if err != nil || !result.Allowed {
		return identityhttp.ErrUnavailable
	}
	return nil
}

func reject(w http.ResponseWriter, _ *http.Request, err error) {
	f := failure{status: 503, code: "unavailable"}
	if errors.Is(err, identityhttp.ErrInvalidInput) {
		f = failure{status: 400, code: "invalid_request"}
	}
	var specific failure
	if errors.As(err, &specific) {
		f = specific
	}
	if f.status == 405 {
		allow := f.allow
		if allow == "" {
			allow = http.MethodPost
		}
		w.Header().Set("Allow", allow)
	}
	if f.retry > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(int64((min(max(f.retry, time.Second), time.Hour)+time.Second-1)/time.Second), 10))
	}
	body := map[string]any{"error": f.code}
	if f.outcome != "" {
		body["commitOutcome"] = f.outcome
	}
	if f.commandID != "" {
		body["commandID"] = f.commandID
	}
	writeJSON(w, f.status, body)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		status = 503
		data = []byte(`{"error":"unavailable"}`)
	}
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}

func absent(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return r.IsNil()
	}
	return false
}

func visible(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for i := range len(value) {
		if value[i] <= 32 || value[i] >= 127 {
			return false
		}
	}
	return true
}

type ingress struct {
	network *identityhttp.NetworkResolver
	decoder *identityhttp.RequestDecoder
	origin  *identityhttp.OriginGuard
}

func newIngress(c identityhttp.NetworkConfig, origin identityhttp.Origin) (*ingress, error) {
	network, err := identityhttp.NewNetworkResolver(c)
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Limits)
	if err != nil {
		return nil, err
	}
	guard, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{origin}, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return nil, err
	}
	return &ingress{network, decoder, guard}, nil
}

func (i *ingress) decode(r *http.Request, operation string, csrf bool) (identityhttp.NetworkFacts, requestBody, identity.IdempotencyKey, error) {
	var facts identityhttp.NetworkFacts
	var body requestBody
	var key identity.IdempotencyKey
	if r.URL.Path != "/v1/passkey/"+operation || r.URL.EscapedPath() != r.URL.Path {
		return facts, body, key, failure{status: 404, code: "not_found"}
	}
	if r.Method != http.MethodPost {
		return facts, body, key, failure{status: 405, code: "method_not_allowed"}
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
		return facts, body, key, identityhttp.ErrInvalidInput
	}
	mode := identityhttp.HeaderForbidden
	if strings.HasSuffix(operation, "options") || operation == "update" || operation == "delete" {
		mode = identityhttp.HeaderRequired
	}
	var err error
	key, _, err = i.decoder.IdempotencyKey(r, mode)
	if err != nil {
		return facts, body, key, identityhttp.ErrInvalidInput
	}
	for name := range r.Header {
		if strings.EqualFold(name, "Authorization") || !csrf && strings.EqualFold(name, "X-CSRF-Token") {
			return facts, body, key, identityhttp.ErrInvalidInput
		}
	}
	facts, err = i.network.Resolve(r)
	if err != nil || facts.Realm() != identityhttp.RealmTenant {
		return facts, body, key, failure{status: 421, code: "misdirected_request"}
	}
	if facts.Scheme() != "https" {
		return facts, body, key, failure{status: 403, code: "https_required"}
	}
	if _, err = i.origin.Check(r); err != nil {
		return facts, body, key, failure{status: 403, code: "origin_denied"}
	}
	fields, err := identityhttp.DecodeJSON[map[string]json.RawMessage](i.decoder, r)
	if err != nil {
		if r.Context().Err() != nil {
			return facts, body, key, identityhttp.ErrUnavailable
		}
		return facts, body, key, identityhttp.ErrInvalidInput
	}
	body, err = decodeBody(operation, fields)
	return facts, body, key, err
}

// Response buffering is an explicit secret-custody policy, not a workflow
// journal. Only this synchronous request owns its bounded bytes. Middleware
// cannot commit cookies, extend original delivery validity or append/replace
// a fresh owned challenge/session response. No streaming profile is selected.
type delivery struct {
	payload      []byte
	status       int
	cookie, csrf string
	valid        func() bool
	deadline     time.Time
	observed     *failure
}
type deliveryKey struct{}

func requestDelivery(r *http.Request) *delivery {
	d, _ := r.Context().Value(deliveryKey{}).(*delivery)
	return d
}
func (d *delivery) render(w http.ResponseWriter, r *http.Request, value any, valid func() bool) {
	data, err := json.Marshal(value)
	if err != nil || len(data) > 300000 {
		reject(w, r, identityhttp.ErrUnavailable)
		return
	}
	d.payload = append(data, '\n')
	d.status = 200
	d.valid = valid
	d.deadline, _ = r.Context().Deadline()
	// Signal status to the pipeline's observer without handing any owned bytes
	// to a middleware writer. Only the final outer guard may flush the payload.
	w.WriteHeader(d.status)
}

type boundedResponse struct {
	header   http.Header
	data     []byte
	status   int
	overflow bool
}

func (b *boundedResponse) Header() http.Header { return b.header }
func (b *boundedResponse) WriteHeader(status int) {
	if b.status == 0 && status >= 200 {
		b.status = status
	}
}
func (b *boundedResponse) Write(data []byte) (int, error) {
	if b.status == 0 {
		b.status = 200
	}
	if len(data) > 300001-len(b.data) {
		b.overflow = true
		return 0, identityhttp.ErrUnavailable
	}
	b.data = append(b.data, data...)
	return len(data), nil
}

type protectedPipeline struct {
	pipeline http.Handler
	maximum  time.Duration
}

func (p *protectedPipeline) WithOperationMiddleware(m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if p == nil || p.pipeline == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.WithOperationMiddleware(p.pipeline, m)
	if err != nil {
		return nil, err
	}
	return &protectedPipeline{pipeline: h, maximum: p.maximum}, nil
}
func (p *protectedPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d := &delivery{}
	deadline := time.Now().Add(p.maximum)
	if inbound, ok := r.Context().Deadline(); ok && inbound.Before(deadline) {
		deadline = inbound
	}
	defer func() { clear(d.payload); d.cookie, d.csrf = "", "" }()
	r = r.WithContext(context.WithValue(r.Context(), deliveryKey{}, d))
	b := &boundedResponse{header: make(http.Header)}
	p.pipeline.ServeHTTP(b, r)
	valid := !b.overflow && r.Context().Err() == nil && time.Now().Before(deadline)
	if d.valid != nil {
		valid = valid && safeDelivery(d.valid)
	}
	if d.payload != nil {
		valid = valid && b.status == d.status && len(b.data) == 0 && !d.deadline.IsZero() && time.Now().Before(d.deadline) && safeDelivery(d.valid)
	}
	if !valid || d.observed != nil && d.payload == nil {
		b = &boundedResponse{header: make(http.Header)}
		if d.observed != nil {
			reject(b, r, *d.observed)
		} else {
			reject(b, r, identityhttp.ErrUnavailable)
		}
		d.cookie, d.csrf = "", ""
	}
	for name, values := range b.header {
		lower := strings.ToLower(name)
		if lower == "set-cookie" || lower == "x-csrf-token" || lower == "authorization" || lower == "location" || lower == "trailer" || strings.HasPrefix(lower, "trailer:") || strings.HasPrefix(lower, "access-control-") || strings.HasPrefix(lower, "x-mfa-") {
			continue
		}
		w.Header()[name] = append([]string(nil), values...)
	}
	w.Header().Del("Set-Cookie")
	w.Header().Del("X-CSRF-Token")
	w.Header().Del("Authorization")
	w.Header().Del("Location")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if valid && d.payload != nil && d.cookie != "" && d.csrf != "" {
		w.Header().Set("Set-Cookie", d.cookie)
		w.Header().Set("X-CSRF-Token", d.csrf)
	}
	status := b.status
	if status == 0 {
		status = 200
	}
	w.WriteHeader(status)
	if valid && d.payload != nil {
		_, _ = w.Write(d.payload)
	} else {
		_, _ = w.Write(b.data)
	}
}
func safeDelivery(check func() bool) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	return check != nil && check()
}
