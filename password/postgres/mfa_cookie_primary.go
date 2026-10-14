package passwordpostgres

import (
	"slices"

	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

// NewCookieMFAEnablePrimarySource selects retained session synchronizer keys
// for cookie enable and native pending-enrollment management. Base must be configured;
// 1..4 nonzero, distinct key versions are copied without mutating Base. It owns
// no resource, callback, IO or transaction. Missing state never falls back to
// bearer-only disclosure. EnableRequest must explicitly supply CSRFToken to
// select cookie custody; zero remains the distinct bearer workflow. Selection
// alone grants no URI or mutation authority.
func NewCookieMFAEnablePrimarySource(base *MFAEnablePrimarySource, keys []session.CSRFKey) (*MFAEnablePrimarySource, error) {
	if base == nil || base.source == nil || base.validator == nil || len(base.csrfKeys) != 0 || len(keys) < 1 || len(keys) > 4 {
		return nil, password.ErrPasswordWork
	}
	for i, key := range keys {
		if key.Version() == 0 {
			return nil, password.ErrPasswordWork
		}
		for _, prior := range keys[:i] {
			if prior.Version() == key.Version() {
				return nil, password.ErrPasswordWork
			}
		}
	}
	copy := *base
	copy.csrfKeys = slices.Clone(keys)
	return &copy, nil
}
