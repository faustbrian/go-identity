package email

import (
	"fmt"
	"io"
	"log/slog"
)

// Format redacts the personal pagination position for every diagnostic verb.
func (Cursor) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "email.Cursor(redacted)") }

// LogValue returns only a constant marker.
func (Cursor) LogValue() slog.Value { return slog.StringValue("email.Cursor(redacted)") }

// MarshalJSON denies implicit export; transport owns explicit output.
func (Cursor) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit text and map-key export.
func (Cursor) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts target and trusted caller metadata.
func (AddressGetRequest) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "email.AddressGetRequest(redacted)")
}

// LogValue returns only a constant marker.
func (AddressGetRequest) LogValue() slog.Value {
	return slog.StringValue("email.AddressGetRequest(redacted)")
}

// MarshalJSON denies implicit request export.
func (AddressGetRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit text and map-key export.
func (AddressGetRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts the authorized address observation.
func (AddressGetResult) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "email.AddressGetResult(redacted)")
}

// LogValue returns only a constant marker.
func (AddressGetResult) LogValue() slog.Value {
	return slog.StringValue("email.AddressGetResult(redacted)")
}

// MarshalJSON denies implicit result export; transport owns safe output fields.
func (AddressGetResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit text and map-key export.
func (AddressGetResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts scope, cursor and trusted caller metadata.
func (AddressListRequest) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "email.AddressListRequest(redacted)")
}

// LogValue returns only a constant marker.
func (AddressListRequest) LogValue() slog.Value {
	return slog.StringValue("email.AddressListRequest(redacted)")
}

// MarshalJSON denies implicit request export.
func (AddressListRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit text and map-key export.
func (AddressListRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts address observations and their pagination position.
func (AddressListResult) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "email.AddressListResult(redacted)")
}

// LogValue returns only a constant marker.
func (AddressListResult) LogValue() slog.Value {
	return slog.StringValue("email.AddressListResult(redacted)")
}

// MarshalJSON denies implicit result export; transport owns safe output fields.
func (AddressListResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit text and map-key export.
func (AddressListResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
