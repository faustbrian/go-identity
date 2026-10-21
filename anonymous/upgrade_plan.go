package anonymous

import (
	"cmp"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	identity "github.com/faustbrian/go-identity"
)

// ConflictDisposition records an explicit per-field/resource decision, never
// permission to transfer it. The native owner must separately admit every
// selected resource and current target credential. Zero and unknown deny.
type ConflictDisposition uint8

const (
	// Unspecified never authorizes an implicit merge policy.
	Unspecified ConflictDisposition = iota
	// KeepSource selects source data only where the owning resource permits it.
	KeepSource
	// KeepTarget preserves the existing permanent account's field or resource.
	KeepTarget
	// Merge requires the resource owner's explicit bounded merge implementation.
	Merge
	// Reject records a conflict that prevents the proposed upgrade.
	Reject
)

// Conflict names a bounded schema-owned field or resource, not its payload or
// identifier. Field is a lowercase dotted path, at most 128 ASCII bytes, with
// letter-led segments and internal digits, underscores or hyphens. Disposition
// is explicit even when the selected policy rejects the complete upgrade.
type Conflict struct {
	Field       string
	Disposition ConflictDisposition
}

// MergePlan binds the original anonymous lifecycle, distinct permanent target
// and every selected conflict decision. It carries no credentials, permission,
// merge callbacks or application payload. A no-transfer plan has no Conflicts.
//
// Caller-owned values must remain unchanged during a call. Validated returns an
// independent canonical snapshot for command fingerprinting; later mutation of
// the input cannot change it. The native owner must still prove target authority,
// exact source version/expiry, complete resource coverage and atomic effects.
// In particular a structurally valid plan cannot force-link credentials or
// revive an expired source. Unsupported transfers must deny before mutation.
type MergePlan struct {
	Source    AnonymousSubject
	Target    identity.SubjectID
	Conflicts []Conflict
}

// Validated checks bounded structure and returns field-sorted owned decisions.
// Duplicate fields deny, including identical decisions: one field has exactly
// one disposition. It does no IO or clock lookup and preserves original expiry;
// planning cannot manufacture or refresh authoritative validity evidence.
func (p MergePlan) Validated() (MergePlan, error) {
	s, err := p.Source.Record()
	if err != nil || s.State != StateActive || s.Version == ^uint64(0) || p.Target == s.ID || len(p.Conflicts) > 64 {
		return MergePlan{}, ErrInvalidInput
	}
	// Permanent UserID preserves existing canonical IDs, including ULIDs; only
	// the newly issued anonymous source uses identity's opaque SubjectID parser.
	// The native owner still applies its canonical-ID policy and real lookup.
	if (identity.User{ID: identity.UserID(p.Target), TenantID: s.TenantID, Status: identity.StatusActive, Version: 1}).Validate(s.TenantID) != nil {
		return MergePlan{}, ErrInvalidInput
	}
	for _, c := range p.Conflicts {
		if !conflictField(c.Field) || c.Disposition < KeepSource || c.Disposition > Reject {
			return MergePlan{}, ErrInvalidInput
		}
	}
	p.Conflicts = slices.Clone(p.Conflicts)
	if len(p.Conflicts) == 0 {
		p.Conflicts = nil
	}
	for n := range p.Conflicts {
		p.Conflicts[n].Field = strings.Clone(p.Conflicts[n].Field)
	}
	slices.SortFunc(p.Conflicts, func(a, b Conflict) int { return cmp.Compare(a.Field, b.Field) })
	for n := 1; n < len(p.Conflicts); n++ {
		if p.Conflicts[n-1].Field == p.Conflicts[n].Field {
			return MergePlan{}, ErrInvalidInput
		}
	}
	return p, nil
}

func conflictField(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	start := true
	for n := range len(name) {
		c := name[n]
		if start {
			if c < 'a' || c > 'z' {
				return false
			}
			start = false
			continue
		}
		if c == '.' {
			if name[n-1] == '-' || name[n-1] == '_' {
				return false
			}
			start = true
		} else if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return !start && name[len(name)-1] != '-' && name[len(name)-1] != '_'
}

func (MergePlan) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte("anonymous.MergePlan(redacted)")) }
func (MergePlan) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (MergePlan) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
func (MergePlan) LogValue() slog.Value         { return slog.StringValue("anonymous.MergePlan(redacted)") }
func (Conflict) Format(f fmt.State, _ rune)    { _, _ = f.Write([]byte("anonymous.Conflict(redacted)")) }
func (Conflict) MarshalJSON() ([]byte, error)  { return nil, ErrDisclosure }
func (Conflict) MarshalText() ([]byte, error)  { return nil, ErrDisclosure }
func (Conflict) LogValue() slog.Value          { return slog.StringValue("anonymous.Conflict(redacted)") }
