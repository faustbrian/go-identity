package mfapostgres

import (
	"bytes"
	"encoding/json"
	"io"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

const maximumContinuationScope = 8192

// Only explicit store encoding bypasses the public redacting marshaler. The
// representation has no bearer or factor secret; it is never a transport DTO.
type storedContinuationSpec mfa.ContinuationSpec
type storedContinuationScope struct {
	Profile  string
	Scope    storedContinuationSpec
	Remember session.RememberPolicySpec
}

func encodeContinuationScope(c mfa.PartialAuthContinuation) ([]byte, error) {
	s, err := c.Bindings()
	if err != nil {
		return nil, invalidAuthority()
	}
	remember, err := s.RememberPolicy.Bindings()
	if err != nil {
		return nil, invalidAuthority()
	}
	s.State, s.Version, s.AttemptsRemaining = mfa.Pending, 1, s.MaxAttempts
	s.RememberPolicy = session.RememberPolicy{}
	wire, err := json.Marshal(storedContinuationScope{"identity-mfa-postgres-continuation-v1", storedContinuationSpec(s), remember})
	if err != nil || len(wire) > maximumContinuationScope {
		clear(wire)
		return nil, invalidAuthority()
	}
	return wire, nil
}

func decodeContinuationScope(wire []byte, digest [32]byte, state mfa.ContinuationState, version uint64, remaining uint32) (mfa.PartialAuthContinuation, error) {
	if len(wire) == 0 || len(wire) > maximumContinuationScope || digest == ([32]byte{}) {
		return mfa.PartialAuthContinuation{}, identity.ForbiddenError{}
	}
	var stored storedContinuationScope
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil || stored.Profile != "identity-mfa-postgres-continuation-v1" {
		return mfa.PartialAuthContinuation{}, identity.ForbiddenError{}
	}
	if decoder.Decode(new(any)) != io.EOF {
		return mfa.PartialAuthContinuation{}, identity.ForbiddenError{}
	}
	s := mfa.ContinuationSpec(stored.Scope)
	if s.State != mfa.Pending || s.Version != 1 || s.AttemptsRemaining != s.MaxAttempts {
		return mfa.PartialAuthContinuation{}, identity.ForbiddenError{}
	}
	remember, err := session.NewRememberPolicy(stored.Remember)
	if err != nil {
		return mfa.PartialAuthContinuation{}, identity.ForbiddenError{}
	}
	s.RememberPolicy = remember
	original, err := mfa.NewPartialAuthContinuation(s)
	if err != nil {
		return mfa.PartialAuthContinuation{}, identity.ForbiddenError{}
	}
	canonical, err := encodeContinuationScope(original)
	defer clear(canonical)
	// Byte equality rejects duplicates, ambiguous numbers, ignored private
	// remember fields and noncanonical representations before they reach storage.
	actual, digestErr := original.ScopeDigest()
	if err != nil || digestErr != nil || actual != digest || !bytes.Equal(canonical, wire) {
		return mfa.PartialAuthContinuation{}, identity.ForbiddenError{}
	}
	s.State, s.Version, s.AttemptsRemaining = state, version, remaining
	restored, err := mfa.NewPartialAuthContinuation(s)
	if err != nil {
		return mfa.PartialAuthContinuation{}, identity.ForbiddenError{}
	}
	return restored, nil
}
