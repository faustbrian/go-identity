package postgres

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func initiationFixture(t *testing.T) (*Contributor, identity.Command, kernel.RequestKeyPreparationBinding) {
	t.Helper()
	p, command, plan := preparedSendFixture(t)
	r, _, err := p.originalPreparedSend(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := command.Feature()
	flow, _ := r.continuation.Bindings()
	eligibility := kernel.RecipientVerified
	if flow.Scope.Purpose == otp.PurposeEmailVerification || flow.Scope.Purpose == otp.PurposeEmailChange {
		eligibility = kernel.RecipientPendingOrVerified
	}
	selected := kernel.RecipientRecord{
		Query:                kernel.RecipientQuery{TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, Kind: identity.IdentifierEmail, CanonicalValue: flow.Scope.Destination.Value(), Eligibility: eligibility},
		User:                 identity.User{ID: spec.Binding.UserID, TenantID: spec.Binding.TenantID, Status: identity.StatusActive, Version: 7},
		Identifier:           identity.Identifier{ID: "email", UserID: spec.Binding.UserID, Kind: identity.IdentifierEmail, CanonicalValue: flow.Scope.Destination.Value(), Verified: true, Primary: true, Version: 9},
		Verification:         identity.Verification{IdentifierID: "email", State: identity.VerificationVerified, VerifiedAt: r.issuedAt, Version: 3},
		UserAuthorityVersion: 11, IdentifierAuthorityVersion: 12, CredentialAuthorityVersion: 13, ObservedAt: r.issuedAt,
	}
	r.recipient = &selected
	bearer, _ := command.SessionToken()
	command, err = p.mapPreparedSendRequest(context.Background(), r, spec.Binding, bearer)
	if err != nil {
		t.Fatal(err)
	}
	b := kernel.RequestKeyPreparationBinding{Namespace: "environment", Scope: kernel.RequestKeyScope{TenantID: spec.Binding.TenantID, ActorID: spec.Binding.ActorID, ActorKind: spec.Binding.ActorKind, Method: "POST", RouteID: spec.Operation.OperationID}, Admission: kernel.RequestKeyAdmission{CommandID: spec.Binding.CommandID, FingerprintKeyVersion: 1}, Feature: *plan.Feature, PolicyVersion: 9, IntentDigest: [32]byte{0x17}}
	return p, command, b
}

func TestSendInitiationAuthenticatesOriginalInputAcrossRestart(t *testing.T) {
	p, original, b := initiationFixture(t)
	risk := sendInitiationRisk{network: "192.0.2.8", device: "device-original", identifierDigest: strings.Repeat("a", 64)}
	wire, err := p.sealSendInitiation(context.Background(), b, original, risk, false)
	if err != nil || len(wire) == 0 {
		t.Fatal("original input was not protected", err)
	}
	bearer, _ := original.SessionToken()
	spec, _ := original.Feature()
	for _, secret := range []string{bearer.Token(), "device-original", "192.0.2.8"} {
		if bytes.Contains(wire, []byte(secret)) {
			t.Fatal("plaintext initiation persisted")
		}
	}
	want, _, _ := p.originalPreparedSend(context.Background(), original)
	fresh := *p
	fresh.codec, err = NewAttemptCodec(codecConfig())
	if err != nil {
		t.Fatal(err)
	}
	restored, err := fresh.restoreSendInitiation(context.Background(), b, wire, bearer)
	if err != nil {
		t.Fatal("original input did not survive restart", err)
	}
	got, _ := restored.original.Feature()
	if !reflect.DeepEqual(got, spec) || restored.risk != risk || restored.attempt != string(b.Admission.CommandID) || restored.suppressed {
		t.Fatal("initiation provenance changed")
	}
	r, _, err := fresh.originalPreparedSend(context.Background(), restored.original)
	if err != nil || !r.issuedAt.Equal(want.issuedAt) || !r.expiresAt.Equal(want.expiresAt) || !reflect.DeepEqual(r.recipient, want.recipient) || r.authority != want.authority {
		t.Fatal("original recipient/authority/time refreshed", err)
	}
	if _, present := restored.original.OneTimeCode(); present {
		t.Fatal("initiation became submitted code")
	}
	wrong := auth.NewBearerCredential("session-token-wrong")
	for _, token := range []auth.BearerCredential{{}, wrong} {
		if _, err := fresh.restoreSendInitiation(context.Background(), b, wire, token); err == nil {
			t.Fatal("stored ciphertext became bearer possession")
		}
	}
}

func TestSendInitiationBindsEveryKernelProvenanceField(t *testing.T) {
	p, original, b := initiationFixture(t)
	risk := sendInitiationRisk{network: "192.0.2.8", device: "device", identifierDigest: strings.Repeat("a", 64)}
	wire, err := p.sealSendInitiation(context.Background(), b, original, risk, false)
	if err != nil {
		t.Fatal(err)
	}
	bearer, _ := original.SessionToken()
	for _, alter := range []func(*kernel.RequestKeyPreparationBinding){
		func(b *kernel.RequestKeyPreparationBinding) { b.Namespace = "foreign" },
		func(b *kernel.RequestKeyPreparationBinding) { b.Scope.TenantID = "foreign" },
		func(b *kernel.RequestKeyPreparationBinding) { b.Scope.ActorID = "foreign" },
		func(b *kernel.RequestKeyPreparationBinding) { b.Scope.ActorKind = "api-key" },
		func(b *kernel.RequestKeyPreparationBinding) { b.Scope.Method = "DELETE" },
		func(b *kernel.RequestKeyPreparationBinding) { b.Scope.RouteID = "identity.otp.other" },
		func(b *kernel.RequestKeyPreparationBinding) { b.Admission.CommandID = "AgICAgICAgICAgICAgICAg" },
		func(b *kernel.RequestKeyPreparationBinding) { b.Admission.FingerprintKeyVersion++ },
		func(b *kernel.RequestKeyPreparationBinding) { b.Feature.Contributor.Owner = "identity/other/postgres" },
		func(b *kernel.RequestKeyPreparationBinding) { b.Feature.Contributor.ContractID = "foreign" },
		func(b *kernel.RequestKeyPreparationBinding) { b.Feature.Contributor.Version++ },
		func(b *kernel.RequestKeyPreparationBinding) { b.Feature.Operation.Owner = "identity/other" },
		func(b *kernel.RequestKeyPreparationBinding) { b.Feature.Operation.OperationID = "identity.otp.other" },
		func(b *kernel.RequestKeyPreparationBinding) { b.Feature.Operation.SchemaID = "foreign" },
		func(b *kernel.RequestKeyPreparationBinding) { b.Feature.Operation.SchemaVersion++ },
		func(b *kernel.RequestKeyPreparationBinding) {
			b.Feature.Operation.RecordRequirement = identity.FeatureRecordOmitted
		},
		func(b *kernel.RequestKeyPreparationBinding) {
			b.Feature.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
		},
		func(b *kernel.RequestKeyPreparationBinding) { b.PolicyVersion++ },
		func(b *kernel.RequestKeyPreparationBinding) { b.IntentDigest[0] ^= 1 },
	} {
		changed := b
		alter(&changed)
		if _, err := p.restoreSendInitiation(context.Background(), changed, wire, bearer); err == nil {
			t.Fatal("transplanted initiation accepted")
		}
	}
	changed := bytes.Clone(wire)
	changed[len(changed)-1] ^= 1
	if _, err := p.restoreSendInitiation(context.Background(), b, changed, bearer); err == nil {
		t.Fatal("tampered original input accepted")
	}
	copy := *p
	profile := *p.send
	profile.configuration[0] ^= 1
	copy.send = &profile
	if _, err := copy.restoreSendInitiation(context.Background(), b, wire, bearer); err == nil {
		t.Fatal("changed configuration adopted original input")
	}
}

func TestSendInitiationSuppressionCannotBecomeIssuance(t *testing.T) {
	p, original, b := initiationFixture(t)
	request, _, err := p.originalPreparedSend(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	request.recipient = nil
	spec, _ := original.Feature()
	bearer, _ := original.SessionToken()
	original, err = p.mapPreparedSendRequest(context.Background(), request, spec.Binding, bearer)
	if err != nil {
		t.Fatal(err)
	}
	risk := sendInitiationRisk{network: "2001:db8::1", device: "device", identifierDigest: strings.Repeat("b", 64)}
	wire, err := p.sealSendInitiation(context.Background(), b, original, risk, true)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := p.restoreSendInitiation(context.Background(), b, wire, bearer)
	if err != nil || !restored.suppressed || restored.request.recipient != nil || restored.risk != risk {
		t.Fatal("suppressed original changed", err)
	}
	if _, present := restored.original.Feature(); present {
		t.Fatal("suppression restored executable issuance")
	}
	if _, err := p.preparedSendPlan(restored.original, nil); err == nil {
		t.Fatal("suppression entered ordinary issuance")
	}
	if _, err := p.restoreSendInitiation(context.Background(), b, wire, auth.BearerCredential{}); err == nil {
		t.Fatal("suppression skipped bearer possession")
	}
	if _, err := p.sealSendInitiation(context.Background(), b, original, risk, false); err == nil {
		t.Fatal("missing recipient became selected issuance")
	}
	p, selected, b := initiationFixture(t)
	if _, err := p.sealSendInitiation(context.Background(), b, selected, risk, true); err == nil {
		t.Fatal("selected recipient became suppressed")
	}
}

func TestSendInitiationClosedParserAndCancellation(t *testing.T) {
	p, original, b := initiationFixture(t)
	request, _, err := p.originalPreparedSend(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := original.Feature()
	risk := sendInitiationRisk{network: "192.0.2.8", device: "device", identifierDigest: strings.Repeat("a", 64)}
	plain, err := encodeSendInitiation(request, spec.Binding, risk, false)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	for end := 0; end < len(plain); end++ {
		if _, err := decodeSendInitiation(plain[:end], b); err == nil {
			t.Fatalf("truncated frame accepted at %d", end)
		}
	}
	for _, data := range [][]byte{append(bytes.Clone(plain), 0), bytes.Repeat([]byte{'x'}, maximumSendInitiation+1)} {
		if _, err := decodeSendInitiation(data, b); err == nil {
			t.Fatal("unbounded or trailing frame accepted")
		}
	}
	for _, bad := range []sendInitiationRisk{
		{network: "192.0.2.008", device: "device", identifierDigest: risk.identifierDigest},
		{network: "fe80::1%en0", device: "device", identifierDigest: risk.identifierDigest},
		{network: risk.network, device: "two devices", identifierDigest: risk.identifierDigest},
		{network: risk.network, device: strings.Repeat("x", 129), identifierDigest: risk.identifierDigest},
		{network: risk.network, device: string([]byte{0xff}), identifierDigest: risk.identifierDigest},
		{network: risk.network, device: risk.device, identifierDigest: strings.Repeat("A", 64)},
		{network: risk.network, device: risk.device, identifierDigest: strings.Repeat("a", 63)},
	} {
		if _, err := encodeSendInitiation(request, spec.Binding, bad, false); err == nil {
			t.Fatal("invalid risk dimensions accepted")
		}
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := p.sealSendInitiation(ctx, b, original, risk, false); !errors.Is(err, context.Canceled) {
		t.Fatal("seal lost cancellation", err)
	}
	wire, err := p.sealSendInitiation(context.Background(), b, original, risk, false)
	if err != nil {
		t.Fatal(err)
	}
	bearer, _ := original.SessionToken()
	if _, err := p.restoreSendInitiation(ctx, b, wire, bearer); !errors.Is(err, context.Canceled) {
		t.Fatal("restore lost cancellation", err)
	}
}

func FuzzSendInitiationParser(f *testing.F) {
	f.Add(uint32(0), []byte{})
	f.Add(uint32(len(sendInitiationPrefix)), []byte{0xff, 0xff})
	f.Add(uint32(512), []byte{0, 1, 2, 255})
	f.Fuzz(func(t *testing.T, offset uint32, mutation []byte) {
		if len(mutation) > maximumSendInitiation {
			t.Skip()
		}
		p, original, b := initiationFixture(t)
		request, _, err := p.originalPreparedSend(context.Background(), original)
		if err != nil {
			t.Fatal(err)
		}
		spec, _ := original.Feature()
		risk := sendInitiationRisk{network: "192.0.2.8", device: "device", identifierDigest: strings.Repeat("a", 64)}
		data, err := encodeSendInitiation(request, spec.Binding, risk, false)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(data)
		start := int(offset % uint32(len(data)))
		copy(data[start:], mutation)
		parsed, err := decodeSendInitiation(data, b)
		if err == nil {
			if parsed.attempt != string(b.Admission.CommandID) || parsed.suppressed || parsed.request.recipient == nil || !validInitiationRisk(parsed.risk) {
				t.Fatal("accepted frame violated initiation invariants")
			}
		}
	})
}
