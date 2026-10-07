package identity

import (
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
)

// RequestIntent freezes complete request input before generated values,
// current-state preparation or command reservation. It is correlation input,
// never authentication, authorization, a reservation or an execution receipt.
// Zero is invalid. Copies are immutable and safe for concurrent reads.
// Raw passwords, bearers and provider tokens are forbidden: feature owners
// supply purpose-bound keyed digests and map every behavior-bearing field.
type RequestIntent struct{ state *requestIntentState }

// A private closure hides fields from recursive diagnostics through private
// caller wrappers; pointer indirection alone leaks on unsupported fmt verbs.
type requestIntentState struct{ fields func() []FeatureField }

// NewRequestIntent validates and copies 0..128 distinct named scalars using
// FeatureField bounds, with at most 256 KiB total. Input order has no meaning;
// absent fields remain distinct from explicitly empty/false/zero values. Time
// preserves its microsecond-exact instant in UTC. No I/O or callbacks run.
// Invalid input returns redacted InvalidInputError and no usable intent. Do not
// mutate caller-owned input during construction. Owners still validate their
// native schema before admission; structural construction grants no authority.
func NewRequestIntent(fields []FeatureField) (RequestIntent, error) {
	if !validFeatureFields(fields) {
		return RequestIntent{}, InvalidInputError{Field: "request_intent"}
	}
	copy := cloneFeatureSpec(FeatureCommandSpec{Fields: fields}).Fields
	slices.SortFunc(copy, func(a, b FeatureField) int { return strings.Compare(a.Name, b.Name) })
	return RequestIntent{state: &requestIntentState{fields: func() []FeatureField { return copy }}}, nil
}

// Fields returns an owned scalar projection only for trusted adapter canonical
// mapping. It returns false for zero. Mutating the result never changes intent.
// The projection is not a disclosure boundary: never log, serialize or return
// its private values through HTTP. No I/O or callbacks run.
func (r RequestIntent) Fields() ([]FeatureField, bool) {
	if r.state == nil {
		return nil, false
	}
	return cloneFeatureSpec(FeatureCommandSpec{Fields: r.state.fields()}).Fields, true
}

// Format redacts every diagnostic verb, including %#v and %x.
func (RequestIntent) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "identity.RequestIntent(redacted)")
}

// MarshalJSON rejects implicit persistence and accidental HTTP disclosure.
func (RequestIntent) MarshalJSON() ([]byte, error) {
	return nil, InvalidInputError{Field: "request_intent_serialization"}
}

// MarshalText rejects implicit text disclosure of private request inputs.
func (RequestIntent) MarshalText() ([]byte, error) {
	return nil, InvalidInputError{Field: "request_intent_serialization"}
}

// LogValue emits no request fields or digests.
func (RequestIntent) LogValue() slog.Value {
	return slog.StringValue("identity.RequestIntent(redacted)")
}
