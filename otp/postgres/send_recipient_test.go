package postgres

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestSendRequestPreservesSelectedRecipientWithoutRetargeting(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		_, challenge, spec, _, authority := issuanceCustodyFixture(t, authenticated)
		s, _ := challenge.Bindings()
		b, _ := s.Continuation.Bindings()
		user := spec.Binding.UserID
		if user == "" {
			user = "discovered-user"
		}
		eligibility := kernel.RecipientVerified
		if b.Scope.Purpose == otp.PurposeEmailVerification || b.Scope.Purpose == otp.PurposeEmailChange {
			eligibility = kernel.RecipientPendingOrVerified
		}
		r := kernel.RecipientRecord{
			Query:                kernel.RecipientQuery{TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, Kind: identity.IdentifierEmail, CanonicalValue: b.Scope.Destination.Value(), Eligibility: eligibility},
			User:                 identity.User{ID: user, TenantID: spec.Binding.TenantID, Status: identity.StatusActive, Version: 7},
			Identifier:           identity.Identifier{ID: "email", UserID: user, Kind: identity.IdentifierEmail, CanonicalValue: b.Scope.Destination.Value(), DisplayValue: "Original display", Verified: true, Primary: true, Version: 9},
			Verification:         identity.Verification{IdentifierID: "email", State: identity.VerificationVerified, VerifiedAt: s.IssuedAt, Version: 3},
			UserAuthorityVersion: 11, IdentifierAuthorityVersion: 12, CredentialAuthorityVersion: 13, ObservedAt: s.IssuedAt,
		}
		if err := r.Validate(); err != nil {
			t.Fatal("invalid recipient fixture", err)
		}
		request := sendRequestRecord{continuation: s.Continuation, policy: s.Policy, authority: authority, issuedAt: s.IssuedAt, expiresAt: s.ExpiresAt, recipient: &r}
		wire, err := encodeSendRequestRecord(request, spec.Binding)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := decodeSendRequestRecord(wire, spec.Binding)
		if err != nil || restored.recipient == nil || !reflect.DeepEqual(*restored.recipient, r) {
			t.Fatal("original recipient selection lost or renewed", err)
		}
		flow, _ := restored.continuation.Bindings()
		if flow.Scope.SubjectID != string(spec.Binding.UserID) || restored.authority != authority {
			t.Fatal("recipient discovery retargeted original flow or authority")
		}
		again, err := encodeSendRequestRecord(restored, spec.Binding)
		if err != nil || !bytes.Equal(wire, again) {
			t.Fatal("recipient custody is not canonical", err)
		}
		for n := range len(wire) {
			if _, err := decodeSendRequestRecord(wire[:n], spec.Binding); err == nil {
				t.Fatal("truncated recipient custody accepted")
			}
		}
		for _, alter := range []func(*kernel.RecipientRecord){
			func(r *kernel.RecipientRecord) { r.Query.TenantID = "foreign" },
			func(r *kernel.RecipientRecord) { r.Query.CanonicalValue = "different@example.test" },
			func(r *kernel.RecipientRecord) { r.Query.Kind = identity.IdentifierPhone },
			func(r *kernel.RecipientRecord) { r.Query.UserID = "foreign-user" },
			func(r *kernel.RecipientRecord) { r.Query.Eligibility = 3 - eligibility },
			func(r *kernel.RecipientRecord) { r.Suppressed = true },
		} {
			copy := r
			alter(&copy)
			request.recipient = &copy
			if _, err := encodeSendRequestRecord(request, spec.Binding); err == nil {
				t.Fatal("mismatched recipient entered original custody")
			}
		}
	}
}

func FuzzSendRecipientFrame(f *testing.F) {
	now := time.Unix(100, 0).UTC()
	r := kernel.RecipientRecord{
		Query:                kernel.RecipientQuery{TenantID: "tenant", Kind: identity.IdentifierEmail, CanonicalValue: "recipient@example.test", Eligibility: kernel.RecipientVerified},
		User:                 identity.User{ID: "user", TenantID: "tenant", Status: identity.StatusActive, Version: 1},
		Identifier:           identity.Identifier{ID: "email", UserID: "user", Kind: identity.IdentifierEmail, CanonicalValue: "recipient@example.test", Verified: true, Version: 1},
		Verification:         identity.Verification{IdentifierID: "email", State: identity.VerificationVerified, VerifiedAt: now, Version: 1},
		UserAuthorityVersion: 1, IdentifierAuthorityVersion: 1, CredentialAuthorityVersion: 1, ObservedAt: now,
	}
	f.Add(appendSendRecipient(nil, r))
	r.Query.Kind, r.Identifier.Kind = identity.IdentifierPhone, identity.IdentifierPhone
	r.Query.CanonicalValue, r.Identifier.CanonicalValue = "+12025550123", "+12025550123"
	r.Identifier.ID, r.Verification.IdentifierID = "phone", "phone"
	r.Query.NormalizationProfile, r.Identifier.NormalizationProfile = "identity.phone.e164-ascii-v1.metadata-v9.0.40", "identity.phone.e164-ascii-v1.metadata-v9.0.40"
	r.Query.NormalizationVersion, r.Identifier.NormalizationVersion = 1, 1
	f.Add(appendSendRecipient(nil, r))
	f.Add([]byte(profiledRecipientPrefix))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{255}, 8192))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			return
		}
		reader := recordReader{data: data, ok: true}
		selected, err := readSendRecipient(&reader)
		if err == nil && len(reader.data) == 0 {
			if selected.Validate() != nil || selected.Suppressed || !bytes.Equal(appendSendRecipient(nil, selected), data) {
				t.Fatal("recipient parser admitted noncanonical custody")
			}
		}
	})
}

func TestPreparedSendRetainsRecipientAcrossGeneratedCustodyAndRestart(t *testing.T) {
	p, original, _ := preparedSendFixture(t)
	r, _, err := p.originalPreparedSend(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := r.continuation.Bindings()
	spec, _ := original.Feature()
	recipient := kernel.RecipientRecord{
		Query:                kernel.RecipientQuery{TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, Kind: identity.IdentifierEmail, CanonicalValue: b.Scope.Destination.Value(), Eligibility: kernel.RecipientVerified},
		User:                 identity.User{ID: spec.Binding.UserID, TenantID: spec.Binding.TenantID, Status: identity.StatusActive, Version: 7},
		Identifier:           identity.Identifier{ID: "email", UserID: spec.Binding.UserID, Kind: identity.IdentifierEmail, CanonicalValue: b.Scope.Destination.Value(), Verified: true, Version: 9},
		Verification:         identity.Verification{IdentifierID: "email", State: identity.VerificationVerified, VerifiedAt: r.issuedAt, Version: 3},
		UserAuthorityVersion: 11, IdentifierAuthorityVersion: 12, CredentialAuthorityVersion: 13, ObservedAt: r.issuedAt,
	}
	if b.Scope.Purpose == otp.PurposeEmailVerification || b.Scope.Purpose == otp.PurposeEmailChange {
		recipient.Query.Eligibility = kernel.RecipientPendingOrVerified
	}
	r.recipient = &recipient
	bearer, _ := original.SessionToken()
	original, err = p.mapPreparedSendRequest(context.Background(), r, spec.Binding, bearer)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := p.GenerateFeaturePreparation(context.Background(), original, 1)
	if err != nil {
		t.Fatal(err)
	}
	generated, _, err := p.RestoreFeaturePreparation(context.Background(), original, 1, wire)
	if err != nil {
		t.Fatal("recipient lost at retained-output restore", err)
	}
	rebuilt, err := p.originalFromGenerated(context.Background(), generated)
	if err != nil {
		t.Fatal(err)
	}
	selected, _, err := p.originalPreparedSend(context.Background(), rebuilt)
	if err != nil || selected.recipient == nil || !reflect.DeepEqual(*selected.recipient, recipient) {
		t.Fatal("generated custody lost original recipient", err)
	}
}
