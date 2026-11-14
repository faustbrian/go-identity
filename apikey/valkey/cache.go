package apikeyvalkey

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

var _ apikey.AtomicVerifier = (*Cache)(nil)
var _ apikey.Store = (*Cache)(nil)

type lookupWire apikey.PositiveProjectionLookup

func (c *Cache) entry(lookup apikey.PositiveProjectionLookup) (string, error) {
	return c.address(lookupWire(lookup), "identity:apikey:p:v1:")
}

type organizationLookupWire apikey.OrganizationPositiveProjectionLookup

func (c *Cache) address(lookup any, prefix string) (string, error) {
	wire, err := json.Marshal(struct {
		Namespace string
		Epoch     uint64
		Lookup    any
	}{c.state.projection.Namespace, c.state.projection.DeploymentEpoch, lookup})
	if err != nil {
		return "", ErrInvalidInput
	}
	mac := hmac.New(sha256.New, []byte(c.state.config.NamespaceKey.state.value))
	_, _ = mac.Write(wire)
	// Full ciphertext AAD checks the complete lookup even in a hash collision.
	// No raw key, presented/stored credential digest, or source fingerprint is
	// part of this address or any transport command.
	return prefix + hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyAndConsume calls the real injected AtomicVerifier exactly once for each
// admitted supplied attempt, warm or cold. It never refills/enforces/debits quota
// itself. Matching retries are still delegated with that same ID. Source denial,
// PossibleDebit and errors pass through without cache work or fallback/retry.
// Only current-source positives reach metadata restore/publication. Application
// business policy and freshness checks remain caller responsibilities.
func (c *Cache) VerifyAndConsume(ctx context.Context, request apikey.AtomicVerificationRequest) (out apikey.AtomicVerificationResult, err error) {
	bounded, done, err := c.begin(ctx)
	if err != nil {
		return out, err
	}
	defer done()
	sourceReturned := false
	defer func() {
		if recover() != nil {
			if !sourceReturned {
				out = apikey.AtomicVerificationResult{AttemptID: request.AttemptID, State: apikey.VerificationAttemptPossibleDebit, Outcome: identity.CommitOutcomeUnknown}
			}
			out.Result = nil
			err = ErrUnavailable
		}
	}()
	admission, current, err := c.state.codec.Begin(bounded, request)
	out = current
	sourceReturned = true
	if err != nil || !admission.Cacheable() {
		return out, err
	}
	key, err := c.admissionEntry(admission)
	if err != nil {
		out.Result = nil
		return out, err
	}
	blob, readErr := c.read(bounded, key)
	defer clear(blob)
	out, publication, err := c.state.codec.Complete(bounded, admission, blob)
	if err != nil {
		return out, err
	}
	if len(publication.Ciphertext) > 0 {
		// Optional publication failure cannot hide or repeat the source outcome.
		if readErr == nil {
			_ = c.publish(bounded, key, publication)
		}
		clear(publication.Ciphertext)
	}
	if out.Result != nil {
		now := c.now()
		if now.IsZero() {
			out.Result = nil
			return out, ErrUnavailable
		}
		if out.Result.ValidateAt(c.state.projection.Configuration, now) != nil {
			out.Result = nil
			return out, apikey.ErrDenied
		}
	}
	return out, nil
}

func (c *Cache) admissionEntry(admission apikey.PositiveProjectionAdmission) (string, error) {
	if c.state.organization {
		lookup, err := admission.OrganizationLookup()
		if err != nil {
			return "", ErrUnavailable
		}
		return c.address(organizationLookupWire(lookup), "identity:apikey:organization:p:v1:")
	}
	lookup, err := admission.Lookup()
	if err != nil {
		return "", ErrUnavailable
	}
	return c.entry(lookup)
}

// ReconcileVerifyAndConsume delegates only the exact original source query.
// It never authenticates a bearer, debits, promotes metadata or renews validity.
func (c *Cache) ReconcileVerifyAndConsume(ctx context.Context, q apikey.VerificationReconcileQuery) (apikey.AtomicVerificationResult, error) {
	bounded, done, err := c.begin(ctx)
	if err != nil {
		return apikey.AtomicVerificationResult{}, err
	}
	defer done()
	return c.state.codec.Reconcile(bounded, q)
}

// ApplyPermissionReduction delegates once to the real server-selected Store,
// never treats a caller decision as mutation authority or performs SQL/debit.
// Success advances the source epochs; old metadata addresses cease matching the
// next native observation even without an event. No outcome is published as a
// fresh verification or principal. The primary remains the sole journal owner.
func (c *Cache) ApplyPermissionReduction(ctx context.Context, d apikey.PermissionReductionDecision) (apikey.PermissionReductionResult, error) {
	bounded, done, err := c.begin(ctx)
	if err != nil {
		return apikey.PermissionReductionResult{}, err
	}
	defer done()
	if d.Validate() != nil || d.Owner.Spec().TenantID != c.state.projection.TenantID {
		return apikey.PermissionReductionResult{}, ErrInvalidInput
	}
	return c.state.projection.Store.ApplyPermissionReduction(bounded, d)
}

// ReconcilePermissionReduction is exact original historical custody only. It
// neither re-decides current policy nor publishes recovered metadata as usable
// authority. Absent/ambiguous status and typed original recovery remain native.
func (c *Cache) ReconcilePermissionReduction(ctx context.Context, q apikey.PermissionReductionReconcileQuery) (apikey.PermissionReductionResult, error) {
	bounded, done, err := c.begin(ctx)
	if err != nil {
		return apikey.PermissionReductionResult{}, err
	}
	defer done()
	if q.Validate() != nil || q.TenantID != c.state.projection.TenantID {
		return apikey.PermissionReductionResult{}, ErrInvalidInput
	}
	return c.state.projection.Store.ReconcilePermissionReduction(bounded, q)
}
