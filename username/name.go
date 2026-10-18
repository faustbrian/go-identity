package username

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/faustbrian/go-identifier/v2"
)

// Name separates immutable lookup identity and original sensitive display.
// Its zero value is invalid. Ordinary formatting/logging is redacted and
// implicit serialization is refused; explicit accessors cross a PII boundary.
type Name struct{ state *nameState }

// Pointer custody prevents fmt from reflecting inline sensitive bytes when a
// consumer's unexported enclosing field bypasses Format. State is immutable.
// Keep the upstream canonical private: returning its inline string-bearing
// value would let the same enclosing-field bypass disclose lookup identity.
type nameState struct {
	canonical identifier.Canonical
	display   string
}

// Record is the deliberately sensitive persistence/wire projection. Preserve
// all fields together; never use Display for uniqueness or log serialized data.
// Exported fields are not proof of validity; use Policy.Restore on load.
type Record struct {
	Canonical      string
	ProfileID      identifier.NormalizationProfileID
	ProfileVersion uint32
	Display        string
}

// Equal compares canonical bytes and exact profile identity/version, independent
// of display. Invalid zero names never compare equal, including to one another.
// Equality is not ownership, availability, authentication, or authorization.
func (n Name) Equal(other Name) bool {
	return n.state != nil && other.state != nil && n.state.canonical.Equal(other.state.canonical)
}

// Display explicitly exposes the exact supplied sensitive display string.
func (n Name) Display() string {
	if n.state == nil {
		return ""
	}
	return n.state.display
}

// Record explicitly exposes sensitive persistence data, or zero for zero Name.
func (n Name) Record() Record {
	if n.state == nil {
		return Record{}
	}
	r := n.state.canonical.Record()
	return Record{Canonical: r.Value, ProfileID: r.ProfileID, ProfileVersion: r.ProfileVersion, Display: n.Display()}
}

// Restore validates exact profile, canonical fixed point, syntax/bounds, and
// that display canonicalizes to the stored identity. It does not reapply today's
// reserved/custom enrollment decisions or establish database ownership.
func (p *Policy) Restore(ctx context.Context, record Record) (Name, error) {
	if record.ProfileID != ProfileID || record.ProfileVersion != ProfileVersion {
		return Name{}, ErrInvalid
	}
	n, err := p.Canonicalize(ctx, record.Display)
	if err != nil {
		return Name{}, err
	}
	if n.state.canonical.Record().Value != record.Canonical {
		return Name{}, ErrInvalid
	}
	if _, err = identifier.RestoreCanonical(identifier.CanonicalRecord{Value: record.Canonical, ProfileID: record.ProfileID, ProfileVersion: record.ProfileVersion}, p.profile); err != nil {
		return Name{}, ErrInvalid
	}
	return n, nil
}

// Format redacts every formatting verb, including quoted and Go syntax.
func (Name) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, "username(redacted)") }

// LogValue redacts structured logs; explicit field logging is not protected.
func (Name) LogValue() slog.Value { return slog.StringValue("username(redacted)") }

// MarshalJSON refuses implicit disclosure; intentionally project Record instead.
func (Name) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }

// MarshalText refuses implicit disclosure; intentionally project Record instead.
func (Name) MarshalText() ([]byte, error) { return nil, ErrDisclosure }

// Format redacts the record although its exported fields remain sensitive.
func (Record) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "username-record(redacted)")
}

// LogValue redacts the record but cannot protect separately logged fields.
func (Record) LogValue() slog.Value { return slog.StringValue("username-record(redacted)") }
