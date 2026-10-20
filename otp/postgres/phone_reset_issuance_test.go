package postgres

import (
	"encoding"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestPhoneResetIssuanceCustodyDoesNotDiscloseNestedState(t *testing.T) {
	if at, until, err := (PhonePasswordResetSendInput{}).Timeline(); err == nil || !at.IsZero() || !until.IsZero() {
		t.Fatal("zero input fabricated an original deadline")
	}
	const marker = "private-request-owner-marker"
	s := &phonePasswordResetIssuer{store: &Contributor{schema: marker}}
	i := phonePasswordResetSendInput{binding: identity.CommandBinding{UserID: marker}}
	p := &preparedPhonePasswordResetSend{input: i}
	for _, value := range []any{
		&PhonePasswordResetIssuer{read: func() *phonePasswordResetIssuer { return s }},
		PhonePasswordResetSendInput{read: func() phonePasswordResetSendInput { return i }},
		PreparedPhonePasswordResetSend{read: func() *preparedPhonePasswordResetSend { return p }},
	} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if strings.Contains(fmt.Sprintf(format, value), marker) || strings.Contains(fmt.Sprintf(format, struct{ hidden any }{value}), marker) {
				t.Fatal("diagnostics traversed opaque request custody")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("JSON serialized native request custody")
		}
		if _, err := value.(encoding.TextMarshaler).MarshalText(); err == nil {
			t.Fatal("text serialized native request custody")
		}
	}
}

// This is the existing OTP input grammar, not live recovery authorization.
// A request-side issuer must preserve the original sessionless recovery flow
// through it rather than relabel the operation as signup, login or enrollment.
func TestPhoneResetIssuanceRequestRetainsOriginalSessionlessSend(t *testing.T) {
	record, binding := phoneResetIssuanceRecordFixture(t)
	wire, err := encodeSendRequestRecord(record, binding)
	if err != nil {
		t.Fatal("existing native send input rejects exact phone-reset request", err)
	}
	defer clear(wire)
	restored, err := decodeSendRequestRecord(wire, binding)
	if err != nil || restored.recipient == nil || restored.authority != record.authority || !restored.issuedAt.Equal(record.issuedAt) || !restored.expiresAt.Equal(record.expiresAt) {
		t.Fatal("phone-reset request changed original send custody", err)
	}
	before, _ := record.continuation.Bindings()
	after, _ := restored.continuation.Bindings()
	beforeFlow, _ := before.Authorization.PreAuthTransaction()
	afterFlow, bound := after.Authorization.PreAuthTransaction()
	beforeOriginal, _ := beforeFlow.Bindings()
	afterOriginal, _ := afterFlow.Bindings()
	if !bound || before.Scope != after.Scope || beforeOriginal != afterOriginal || after.RememberPolicy != (session.RememberPolicy{}) {
		t.Fatal("phone-reset issuance lost original sessionless flow")
	}
}

func TestPhoneResetIssuanceRejectsDifferentOriginalSend(t *testing.T) {
	for name, change := range map[string]func(*sendRequestRecord, *identity.CommandBinding){
		"missing-recipient": func(r *sendRequestRecord, _ *identity.CommandBinding) { r.recipient = nil },
		"recipient-epoch":   func(r *sendRequestRecord, _ *identity.CommandBinding) { r.recipient.IdentifierAuthorityVersion++ },
		"credential":        func(r *sendRequestRecord, _ *identity.CommandBinding) { r.authority.Credential.ID = "other" },
		"non-password": func(r *sendRequestRecord, _ *identity.CommandBinding) {
			r.authority.Credential.Kind = identity.CredentialPasskey
		},
		"request-id":    func(_ *sendRequestRecord, b *identity.CommandBinding) { b.RecordID = "other" },
		"policy":        func(_ *sendRequestRecord, b *identity.CommandBinding) { b.PolicyID = "other" },
		"schema":        func(_ *sendRequestRecord, b *identity.CommandBinding) { b.SchemaID = "other" },
		"extended-time": func(r *sendRequestRecord, _ *identity.CommandBinding) { r.expiresAt = r.expiresAt.Add(time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			r, b := phoneResetIssuanceRecordFixture(t)
			change(&r, &b)
			wire, err := encodeSendRequestRecord(r, b)
			defer clear(wire)
			if err == nil || len(wire) != 0 {
				t.Fatal("different original send entered request custody")
			}
		})
	}
}

func phoneResetIssuanceRecordFixture(t *testing.T) (sendRequestRecord, identity.CommandBinding) {
	t.Helper()
	_, _, input, authority, original := phoneRecoveryCommandFixture(t)
	spec, _ := input.PhonePasswordResetInputFeature()
	binding := spec.Binding
	binding.OperationID = "identity.phone.password-reset-request"
	binding.SchemaID = "identity.phone.password-reset-request.native-v1"
	binding.RecordID = string(binding.CommandID)
	flow, _ := original.Bindings()
	binding.PolicyID, binding.PolicyVersion = flow.Binding.Intent.PolicyID, flow.Binding.Intent.PolicyVersion
	authorization, err := otp.NewBoundPreAuthAuthorization(original)
	if err != nil {
		t.Fatal(err)
	}
	destination, _ := otp.NewDestinationInput("+358401234567")
	continuation, err := otp.NewContinuation(otp.DigestScopeSpec{
		TenantID: string(binding.TenantID), SubjectID: string(binding.UserID),
		Purpose: otp.PurposePasswordReset, Channel: otp.ChannelSMS, Destination: destination,
		ChallengeID: string(binding.CommandID), TargetID: string(authority.Credential.ID),
		PolicyVersion: binding.PolicyVersion, Generation: 1,
	}, authorization, session.RememberPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposePasswordReset, Alphabet: "0123456789", Length: 6, TTL: time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 3, Attempts: 3, Replacement: otp.ReplacePrevious})
	policy, err := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{LockoutAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	at := flow.Binding.IssuedAt
	recipient := kernel.RecipientRecord{
		Query:                kernel.RecipientQuery{TenantID: binding.TenantID, UserID: binding.UserID, Kind: identity.IdentifierPhone, CanonicalValue: destination.Value(), Eligibility: kernel.RecipientVerified},
		User:                 identity.User{ID: binding.UserID, TenantID: binding.TenantID, Status: identity.StatusActive, Version: 1},
		Identifier:           identity.Identifier{ID: "phone", UserID: binding.UserID, Kind: identity.IdentifierPhone, CanonicalValue: destination.Value(), Verified: true, Version: 1},
		Verification:         identity.Verification{IdentifierID: "phone", State: identity.VerificationVerified, VerifiedAt: at, Version: 1},
		UserAuthorityVersion: authority.UserAuthorityVersion, IdentifierAuthorityVersion: authority.IdentifierAuthorityVersion, CredentialAuthorityVersion: authority.CredentialAuthorityVersion, ObservedAt: at,
	}
	if err := recipient.Validate(); err != nil {
		t.Fatal(err)
	}
	return sendRequestRecord{continuation: continuation, policy: policy, authority: authority, issuedAt: at, expiresAt: at.Add(time.Minute), recipient: &recipient}, binding
}
