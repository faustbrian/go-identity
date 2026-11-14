package apikey_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

// This exercises only the root's injected authority seam. Actual organization
// membership, persistence and quota are proven in the native consumer.
type organizationProjectionSource struct {
	*projectionContractSource
	organizationVersion uint64
	ownerUnavailable    bool
	ownerUntil          time.Time
}

func (s *organizationProjectionSource) VerifyAndConsume(ctx context.Context, r apikey.AtomicVerificationRequest) (apikey.AtomicVerificationResult, error) {
	out, err := s.projectionContractSource.VerifyAndConsume(ctx, r)
	if out.Result != nil {
		owner, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: r.TenantID, Kind: apikey.OwnerOrganization, OrganizationID: "organization-a", Version: 2})
		out.Result.Owner, out.Result.Record.Owner = owner, owner
		out.Original.UserID, out.Original.AnonymousFlowID = "", string(r.AttemptID)
		s.last = out
	}
	return out, err
}

func (s *organizationProjectionSource) ObserveOrganizationSourceAuthority(_ context.Context, b apikey.OrganizationSourceAuthorityBinding) (apikey.OrganizationSourceAuthorityObservation, error) {
	s.observations++
	if s.ownerUnavailable {
		return apikey.OrganizationSourceAuthorityObservation{}, apikey.ErrDenied
	}
	r := s.last.Result
	grant := r.Grant
	if s.observedGrant != nil {
		grant = s.observedGrant
	}
	until := r.ValidUntil
	if !s.ownerUntil.IsZero() && s.ownerUntil.Before(until) {
		until = s.ownerUntil
	}
	return apikey.OrganizationSourceAuthorityObservation{Binding: b, Record: r.Record, Owner: r.Owner, Grant: slices.Clone(grant), PolicyVersion: 4, ConfigurationAuthority: b.ConfigurationAuthority, GlobalVersion: 1, TenantVersion: 1, OrganizationVersion: s.organizationVersion, OrganizationCredentialVersion: b.Owner.Version(), ReadStartedAt: r.ReadStartedAt, VerifiedAt: s.now, ValidUntil: until, OrganizationReadStartedAt: r.ReadStartedAt.Add(-time.Millisecond), OrganizationVerifiedAt: r.ReadStartedAt, OrganizationValidUntil: until}, nil
}

func TestOrganizationPositiveProjectionEarliestOwnerExpiryDeniesWithoutRenewal(t *testing.T) {
	_, base, request, config := positiveProjectionFixture(t)
	source := &organizationProjectionSource{projectionContractSource: base, organizationVersion: 3, ownerUntil: base.now.Add(time.Second)}
	config.Verifier, config.Authority = source, nil
	codec, err := apikey.NewOrganizationPositiveProjectionCodec(config, source)
	if err != nil {
		t.Fatal(err)
	}
	admission, original, err := codec.Begin(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	out, publication, err := codec.Complete(context.Background(), admission, nil)
	if err != nil || out.Result == nil || !out.Result.ValidUntil.Equal(source.ownerUntil) || !publication.ValidUntil.Equal(source.ownerUntil) || !out.Result.ValidUntil.Before(base.last.Result.ValidUntil) {
		t.Fatal("organization projection ignored earlier original owner expiry", err)
	}
	source.now = source.ownerUntil
	denied, published, err := codec.Complete(context.Background(), admission, publication.Ciphertext)
	if !errors.Is(err, apikey.ErrDenied) || denied.Result != nil || denied.State != original.State || denied.Fingerprint != original.Fingerprint || denied.Quota == nil || *denied.Quota != *original.Quota || len(published.Ciphertext) != 0 || base.verifications != 1 {
		t.Fatal("expired original organization evidence renewed or lost native debit", err)
	}
	source.ownerUnavailable = true
	if a, denied, err := codec.Begin(context.Background(), request); !errors.Is(err, apikey.ErrDenied) || a.Cacheable() || denied.Result != nil || denied.Quota == nil || base.verifications != 2 {
		t.Fatal("failed bounded owner refresh fell back to old organization metadata", err)
	}
}

func TestOrganizationPositiveProjectionBeginCannotExposeWithdrawnCurrentGrant(t *testing.T) {
	for _, grant := range [][]string{{"invoice.read"}, {"invoice.write"}} {
		t.Run(grant[0], func(t *testing.T) {
			_, base, request, config := positiveProjectionFixture(t)
			source := &organizationProjectionSource{projectionContractSource: base, organizationVersion: 3, ownerUntil: base.now.Add(time.Second)}
			source.observedGrant = grant
			config.Verifier, config.Authority = source, nil
			codec, err := apikey.NewOrganizationPositiveProjectionCodec(config, source)
			if err != nil {
				t.Fatal(err)
			}
			admission, out, err := codec.Begin(context.Background(), request)
			if grant[0] == "invoice.write" {
				if !errors.Is(err, apikey.ErrDenied) || admission.Cacheable() || out.Result != nil || out.Validate() != nil || out.Quota == nil || out.State != apikey.VerificationAttemptDebited {
					t.Fatal("Begin exposed a principal after current required-permission withdrawal", err)
				}
				return
			}
			if err != nil || !admission.Cacheable() || out.Result == nil || !slices.Equal(out.Result.Grant, []string{"invoice.read"}) || !out.Result.ValidUntil.Equal(source.ownerUntil) || out.Result.ReadStartedAt != base.last.Result.ReadStartedAt || out.Result.VerifiedAt != base.last.Result.VerifiedAt || out.Quota == nil || *out.Quota != *base.last.Quota || !slices.Equal(base.last.Result.Grant, []string{"invoice.read", "invoice.write"}) {
				t.Fatal("Begin exposed the old broader native grant/deadline after observing narrower current authority", err)
			}
		})
	}
}

func TestOrganizationPositiveProjectionUsesActualOrganizationOwner(t *testing.T) {
	_, base, request, config := positiveProjectionFixture(t)
	source := &organizationProjectionSource{projectionContractSource: base, organizationVersion: 3}
	config.Verifier = source
	config.Authority = nil
	codec, err := apikey.NewOrganizationPositiveProjectionCodec(config, source)
	if err != nil {
		t.Fatal(err)
	}
	admission, out, err := codec.Begin(context.Background(), request)
	if err != nil || !admission.Cacheable() || out.Result == nil || out.Result.Owner.Spec().Kind != apikey.OwnerOrganization || out.Result.Owner.Spec().UserID != "" {
		t.Fatal("modern organization source cannot reach positive metadata projection", err)
	}
	lookup, err := admission.OrganizationLookup()
	if err != nil || lookup.OwnerKind != apikey.OwnerOrganization || lookup.OrganizationID != out.Result.Owner.Spec().OrganizationID || lookup.OrganizationVersion != 3 || lookup.OrganizationCredentialVersion != 2 || lookup.RootID != out.Result.Record.RootID || lookup.RootVersion != out.Result.Record.RootVersion {
		t.Fatal("organization projection lost actual typed owner/root epochs", err)
	}
	if _, err := admission.Lookup(); err == nil {
		t.Fatal("organization admission exposed a USER lookup")
	}
	first, publication, err := codec.Complete(context.Background(), admission, nil)
	if err != nil || first.Validate() != nil || len(publication.Ciphertext) == 0 || !publication.ReadStartedAt.Equal(out.Result.ReadStartedAt.Add(-time.Millisecond)) {
		t.Fatal("organization projection failed to retain earliest original contributor", err)
	}
	source.now = source.now.Add(4 * time.Second)
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	request.AttemptID = apikey.VerificationAttemptID(id)
	secondAdmission, second, err := codec.Begin(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	warm, promoted, err := codec.Complete(context.Background(), secondAdmission, publication.Ciphertext)
	if err != nil || warm.Result == nil || warm.Quota == nil || warm.Quota.Remaining != 8 || warm.AttemptID != second.AttemptID || warm.Fingerprint != second.Fingerprint || *warm.Quota != *second.Quota || !warm.Result.ValidUntil.Equal(first.Result.ValidUntil) || !promoted.ReadStartedAt.Equal(publication.ReadStartedAt) || !promoted.ValidUntil.Equal(publication.ValidUntil) || base.verifications != 2 || base.observations != 2 {
		t.Fatal("warm organization metadata skipped source, spent cached quota or renewed evidence", err)
	}
	source.ownerUnavailable = true
	deniedAdmission, denied, err := codec.Begin(context.Background(), request)
	if !errors.Is(err, apikey.ErrDenied) || deniedAdmission.Cacheable() || denied.Result != nil || denied.State != apikey.VerificationAttemptDebited || denied.Validate() != nil || denied.Quota == nil || base.verifications != 3 {
		t.Fatal("unavailable organization authority became cached success or lost known debit", err)
	}
}

func TestOrganizationPositiveProjectionUnknownDoesNotReadOrPublish(t *testing.T) {
	_, base, request, config := positiveProjectionFixture(t)
	source := &organizationProjectionSource{projectionContractSource: base, organizationVersion: 3}
	config.Verifier = source
	config.Authority = nil
	base.failure = apikey.ErrDebitOutcomeUnknown{AttemptID: request.AttemptID}
	codec, err := apikey.NewOrganizationPositiveProjectionCodec(config, source)
	if err != nil {
		t.Fatal(err)
	}
	admission, out, err := codec.Begin(context.Background(), request)
	var unknown apikey.ErrDebitOutcomeUnknown
	if !errors.As(err, &unknown) || admission.Cacheable() || out.Result != nil || out.State != apikey.VerificationAttemptPossibleDebit || base.verifications != 1 || base.observations != 0 {
		t.Fatal("organization possible debit was hidden, repeated or observed as usable authority", err)
	}
}

func TestOrganizationPositiveProjectionRejectsMixedAndWrongKindSources(t *testing.T) {
	userCodec, base, request, config := positiveProjectionFixture(t)
	source := &organizationProjectionSource{projectionContractSource: base, organizationVersion: 3}
	if codec, err := apikey.NewOrganizationPositiveProjectionCodec(config, source); err == nil || codec != nil {
		t.Fatal("mixed USER and organization authority selection admitted")
	}
	config.Authority = nil
	if codec, err := apikey.NewOrganizationPositiveProjectionCodec(config, nil); err == nil || codec != nil {
		t.Fatal("source-free organization selection admitted")
	}
	codec, err := apikey.NewOrganizationPositiveProjectionCodec(config, source)
	if err != nil {
		t.Fatal(err)
	}
	admission, out, err := codec.Begin(context.Background(), request)
	if !errors.Is(err, apikey.ErrDenied) || admission.Cacheable() || out.Result != nil {
		t.Fatal("organization codec admitted a USER positive", err)
	}
	userAdmission, _, err := userCodec.Begin(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := userAdmission.OrganizationLookup(); err == nil {
		t.Fatal("USER admission fabricated organization owner epochs")
	}
	config.Authority, config.Verifier = source, source
	userOnly, err := apikey.NewPositiveProjectionCodec(config)
	if err != nil {
		t.Fatal(err)
	}
	if a, out, err := userOnly.Begin(context.Background(), request); !errors.Is(err, apikey.ErrDenied) || a.Cacheable() || out.Result != nil {
		t.Fatal("existing USER constructor silently expanded to organization metadata", err)
	}
}
