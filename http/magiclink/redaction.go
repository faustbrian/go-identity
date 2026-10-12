package magiclinkhttp

import (
	"fmt"
	identityhttp "github.com/faustbrian/go-identity/http"
	"log/slog"
)

// Format redacts borrowed runtime configuration.
func (RequestConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("magiclinkhttp.RequestConfig(redacted)"))
}

// MarshalJSON denies implicit runtime export.
func (RequestConfig) MarshalJSON() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// MarshalText denies implicit textual runtime export.
func (RequestConfig) MarshalText() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// LogValue emits a fixed redacted marker.
func (RequestConfig) LogValue() slog.Value {
	return slog.StringValue("magiclinkhttp.RequestConfig(redacted)")
}

// Format redacts selected operation configuration.
func (FeatureConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("magiclinkhttp.FeatureConfig(redacted)"))
}

// MarshalJSON denies implicit selection export.
func (FeatureConfig) MarshalJSON() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// MarshalText denies implicit textual selection export.
func (FeatureConfig) MarshalText() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// LogValue emits a fixed redacted marker.
func (FeatureConfig) LogValue() slog.Value {
	return slog.StringValue("magiclinkhttp.FeatureConfig(redacted)")
}

// Format redacts borrowed consuming-runtime configuration.
func (ConsumeConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("magiclinkhttp.ConsumeConfig(redacted)"))
}

// MarshalJSON denies implicit runtime export.
func (ConsumeConfig) MarshalJSON() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// MarshalText denies implicit textual runtime export.
func (ConsumeConfig) MarshalText() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// LogValue emits a fixed marker.
func (ConsumeConfig) LogValue() slog.Value {
	return slog.StringValue("magiclinkhttp.ConsumeConfig(redacted)")
}
