package ssohttp

import (
	"context"
	"errors"
	"net/http"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-sso"
)

const (
	samlMetadataOperation = "identity.sso.saml-metadata"
	samlMetadataType      = "application/samlmetadata+xml"
	// Allow one base64-encoded 64 KiB certificate plus the bounded XML fields.
	maximumSAMLMetadataBytes = 96 << 10
)

// SAMLMetadataDocument carries owned public XML for the installed SP and the
// original exclusive deadline of the native observation. Readers must not
// renew that deadline while rendering or caching metadata.
type SAMLMetadataDocument struct {
	XML        []byte
	ValidUntil time.Time
}

// SAMLMetadataReader returns the exact selected SP's public metadata without
// modifying provider state. Implementations must be safe for concurrent use.
type SAMLMetadataReader interface {
	ReadSAMLMetadata(context.Context, identity.TenantID, string) (SAMLMetadataDocument, error)
}

type samlMetadataSelection struct {
	rate   *identityhttp.SafeRateLimiter
	reader SAMLMetadataReader
}

// NewSAMLSigninFeatureWithMetadata adds an anonymous, rate-limited GET for
// the same installed SP as the required signed login and POST ACS pair. It
// does not issue cookies or advertise a separately unmounted login profile.
func NewSAMLSigninFeatureWithMetadata(c SAMLSigninConfig, rate *identityhttp.SafeRateLimiter, reader SAMLMetadataReader) (identityhttp.Feature, error) {
	if !rate.Configured() || !configuredOwner(reader) {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	return newSAMLSigninFeature(c, &samlMetadataSelection{rate: rate, reader: reader})
}

func (p samlSigninProfile) metadataOperation(owner identityhttp.ModuleID, selection samlMetadataSelection) (identityhttp.OperationDescriptor, error) {
	path := "/saml2/" + p.c.ProviderID + "/metadata"
	handler, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[identityhttp.NetworkFacts]{
		MaximumDuration: p.c.MaximumDuration,
		Decode: func(r *http.Request) (identityhttp.NetworkFacts, error) {
			if !exactSAMLRequest(r, http.MethodGet, path) || r.URL.RawQuery != "" ||
				r.ContentLength != 0 || (r.Body != nil && r.Body != http.NoBody) {
				return identityhttp.NetworkFacts{}, identityhttp.ErrInvalidInput
			}
			if _, _, err := p.decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return identityhttp.NetworkFacts{}, err
			}
			return p.requestNetwork(r)
		},
		Authenticate: func(_ *http.Request, facts identityhttp.NetworkFacts) (identityhttp.NetworkFacts, error) {
			return facts, nil
		},
		Admit: func(r *http.Request, facts identityhttp.NetworkFacts) error {
			result, err := selection.rate.Admit(r.Context(), facts, samlMetadataOperation, "")
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return discoveryRateDenial{retry: result.RetryAfter}
			}
			if err != nil || !result.Allowed {
				return sso.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, facts identityhttp.NetworkFacts) {
			out, err := selection.reader.ReadSAMLMetadata(r.Context(), facts.TenantID(), p.c.ProviderID)
			if r.Context().Err() != nil {
				writeSigninError(w, r, sso.ErrUnavailable)
				return
			}
			if errors.Is(err, sso.ErrForbidden) {
				clearSigninHeaders(w)
				writeDiscoveryJSON(w, http.StatusNotFound, struct {
					Error string `json:"error"`
				}{"not_found"})
				return
			}
			now := p.c.Now()
			if err != nil || len(out.XML) == 0 || len(out.XML) > maximumSAMLMetadataBytes || now.IsZero() ||
				!now.Before(out.ValidUntil) || out.ValidUntil.After(now.Add(20*time.Second)) {
				writeSigninError(w, r, sso.ErrUnavailable)
				return
			}
			clearSigninHeaders(w)
			w.Header().Set("Content-Type", samlMetadataType)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(out.XML)
		},
		Reject: writeSigninError,
	})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: owner, OperationID: samlMetadataOperation, Handler: handler, ProviderPathIDs: []string{p.c.ProviderID},
		CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: maximumSAMLMetadataBytes,
	})
	if err != nil {
		return identityhttp.OperationDescriptor{}, err
	}
	op.Wire = samlMetadataWire()
	return op, nil
}
