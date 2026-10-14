package session

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
)

// EnrichmentSchema declares an ordered display-only output schema. Version is
// positive, FieldNames has 1..32 unique visible ASCII names of at most 64 bytes,
// and MaxBytes is 1..16384 total UTF-8 value bytes. The complete immutable
// Session (all bindings, authority and lifetime policy) is always the source.
// No output field overrides a source field, principal or authorization fact.
// Configuration freezes a copy; callback and consumer projections are owned.
type EnrichmentSchema struct {
	Version    uint64
	FieldNames []string
	MaxBytes   uint32
}

// Enrichment is an ordered display-only projection, never authentication or
// authorization evidence. On success Values corresponds exactly to FieldNames;
// empty individual strings are valid. Nil Values means deliberate omission,
// not a schema-shaped successful projection. Returned slices are caller-owned.
// Treat values as untrusted display text; transport owners must escape them.
type Enrichment struct{ Values []string }

// SessionEnricher supplies a bounded deployment callback, not a domain store.
// Enrich must honor ctx and return promptly when cancelled. Implementations
// must be concurrency-safe and keep returned values stable until return.
// Session is structural source data, not proof; do not use it to grant access.
// Callbacks run without session/store locks and cannot replace session state.
type SessionEnricher interface {
	Enrich(context.Context, Session, EnrichmentSchema) (Enrichment, error)
}

// EnrichmentFailurePolicy explicitly controls display callback failure. It
// never controls authentication admission or suppresses context cancellation.
type EnrichmentFailurePolicy uint8

const (
	// EnrichmentFail returns a redacted error and no projection on failure.
	EnrichmentFail EnrichmentFailurePolicy = iota + 1
	// EnrichmentOmit omits display data on callback errors or panics only.
	// Malformed successful output still fails closed rather than being cached.
	EnrichmentOmit
)

// EnrichmentConfig freezes the schema and failure policy. MaximumDuration is
// 1ms..5s; earlier caller deadlines win. Zero configuration is invalid.
type EnrichmentConfig struct {
	Schema          EnrichmentSchema
	MaximumDuration time.Duration
	FailurePolicy   EnrichmentFailurePolicy
}

// EnrichmentService performs uncached display projection on every invocation.
// Complete source changes therefore always rerun enrichment; it owns no cache,
// store lock, goroutine, transaction or authority vector. Calls are safe to run
// concurrently if the borrowed callback is. Keep it alive until calls finish.
// A context budget cannot interrupt a callback that violates its cancellation
// contract; no detached goroutine is created to conceal that violation.
type EnrichmentService struct {
	provider SessionEnricher
	config   EnrichmentConfig
}

// NewEnrichmentService validates and freezes composition without invoking the
// callback or IO. It neither authenticates sessions nor configures transport.
func NewEnrichmentService(provider SessionEnricher, config EnrichmentConfig) (*EnrichmentService, error) {
	if issuerNil(provider) || config.MaximumDuration < time.Millisecond || config.MaximumDuration > 5*time.Second || (config.FailurePolicy != EnrichmentFail && config.FailurePolicy != EnrichmentOmit) || !validEnrichmentSchema(config.Schema) {
		return nil, ErrInvalidInput
	}
	config.Schema = copyEnrichmentSchema(config.Schema)
	return &EnrichmentService{provider, config}, nil
}

func validEnrichmentSchema(s EnrichmentSchema) bool {
	if s.Version == 0 || len(s.FieldNames) < 1 || len(s.FieldNames) > 32 || s.MaxBytes < 1 || s.MaxBytes > 16384 {
		return false
	}
	for i, name := range s.FieldNames {
		if !authorityKey(name, 64) {
			return false
		}
		for _, previous := range s.FieldNames[:i] {
			if previous == name {
				return false
			}
		}
	}
	return true
}

func copyEnrichmentSchema(s EnrichmentSchema) EnrichmentSchema {
	out := s
	out.FieldNames = make([]string, len(s.FieldNames))
	for i, name := range s.FieldNames {
		out.FieldNames[i] = strings.Clone(name)
	}
	return out
}

// Enrich returns schema-ordered, bounded, defensively copied display values.
// A zero session is invalid; a valid structural session is not necessarily
// active. Call this after independent authentication/authorization, and never
// merge its output into principal facts. No authority freshness is renewed.
// Errors and panics are redacted. Cancellation/deadline always return their
// typed classification, never optional fallback or partial output.
func (s *EnrichmentService) Enrich(ctx context.Context, source Session) (out Enrichment, err error) {
	if ctx == nil || s == nil || issuerNil(s.provider) {
		return out, ErrInvalidInput
	}
	if _, err := source.Bindings(); err != nil {
		return out, ErrInvalidInput
	}
	bounded, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out = Enrichment{}
			if bounded.Err() != nil {
				err = sessionReadFailure(bounded)
			} else if s.config.FailurePolicy == EnrichmentOmit {
				err = nil
			} else {
				err = ErrUnavailable
			}
		}
	}()
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	projection, callbackError := s.provider.Enrich(bounded, source, copyEnrichmentSchema(s.config.Schema))
	if bounded.Err() != nil {
		return out, sessionReadFailure(bounded)
	}
	if callbackError != nil {
		var cancelled identity.CancelledError
		var deadline identity.DeadlineExceededError
		if errors.Is(callbackError, context.Canceled) || errors.As(callbackError, &cancelled) {
			return out, identity.CancelledError{}
		}
		if errors.Is(callbackError, context.DeadlineExceeded) || errors.As(callbackError, &deadline) {
			return out, identity.DeadlineExceededError{}
		}
		if s.config.FailurePolicy == EnrichmentOmit {
			return out, nil
		}
		return out, ErrUnavailable
	}
	if len(projection.Values) != len(s.config.Schema.FieldNames) {
		return out, ErrUnavailable
	}
	remaining := int(s.config.Schema.MaxBytes)
	for _, value := range projection.Values {
		if len(value) > remaining || !utf8.ValidString(value) {
			return out, ErrUnavailable
		}
		remaining -= len(value)
	}
	out.Values = make([]string, len(projection.Values))
	for i, value := range projection.Values {
		out.Values[i] = strings.Clone(value)
	}
	if bounded.Err() != nil {
		return Enrichment{}, sessionReadFailure(bounded)
	}
	return out, nil
}

// Format redacts display content and field identities from diagnostics.
func (Enrichment) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("session.Enrichment(redacted)")) }

// Format redacts schema identities from diagnostics.
func (EnrichmentSchema) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.EnrichmentSchema(redacted)"))
}

// Format redacts borrowed callback configuration from diagnostics.
func (EnrichmentConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.EnrichmentConfig(redacted)"))
}

// Format redacts runtime composition from diagnostics.
func (EnrichmentService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.EnrichmentService(redacted)"))
}

// MarshalJSON denies implicit display-data export; transport selects fields explicitly.
func (Enrichment) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalJSON denies implicit schema export.
func (EnrichmentSchema) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalJSON denies implicit callback configuration export.
func (EnrichmentConfig) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalJSON denies implicit runtime export.
func (EnrichmentService) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }
