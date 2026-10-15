package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestTokenlessSessionCustodyHistoricalBytes(t *testing.T) {
	_, _, original := sessionCustodyFixture(t)
	// Independently calculated from the historical v4 field order with Ruby
	// big-endian pack and SHA256, not the current encoder or decoder.
	want := "5a5e169096e99a43fa4f962168f836439f6c182be74d431a32868a749713d54e"
	sum := sha256.Sum256(appendSessionRecord(nil, original))
	if hex.EncodeToString(sum[:]) != want {
		t.Fatal("historical tokenless session bytes changed")
	}
}

func csrfContinuation(t testing.TB, original otp.Continuation) otp.Continuation {
	t.Helper()
	b, _ := original.Bindings()
	s, ok := b.Authorization.AuthenticatedSession()
	if !ok {
		t.Fatal("fixture requires original session")
	}
	base, _ := s.Bindings()
	state, err := session.NewCSRFState(session.CSRFStateSpec{Binding: session.CSRFBinding{TenantID: base.TenantID, SessionID: base.SessionID, SessionVersion: base.Version}, KeyVersion: 7, Digest: [32]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	s, err = session.NewSessionWithCSRF(base, state)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := otp.NewBoundSessionAuthorization(s)
	if err != nil {
		t.Fatal(err)
	}
	b.Scope.AuthorizationBinding = [32]byte{}
	c, err := otp.NewContinuation(b.Scope, flow, b.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func requireOriginalCSRF(t testing.TB, want, got otp.Continuation) {
	t.Helper()
	w, _ := want.Bindings()
	g, _ := got.Bindings()
	ws, _ := w.Authorization.AuthenticatedSession()
	gs, ok := g.Authorization.AuthenticatedSession()
	state, err := gs.CSRFState().Bindings()
	expected, _ := ws.CSRFState().Bindings()
	if !ok || err != nil || state != expected || w.Scope != g.Scope || w.RememberPolicy != g.RememberPolicy || !bytes.Equal(appendSessionRecord(nil, ws), appendSessionRecord(nil, gs)) {
		t.Fatal("original session, CSRF or continuation changed")
	}
}

func requireClosedCSRFFrame(t testing.TB, wire []byte, decode func([]byte) error) {
	t.Helper()
	if err := decode(wire); err != nil {
		t.Fatal("valid frame rejected", err)
	}
	for n := range len(wire) {
		if decode(wire[:n]) == nil {
			t.Fatalf("truncated frame accepted at %d", n)
		}
	}
	if decode(append(bytes.Clone(wire), 0)) == nil {
		t.Fatal("trailing frame accepted")
	}
	if decode(bytes.Repeat([]byte{0}, 8193)) == nil {
		t.Fatal("oversized frame accepted")
	}
}

func TestIssuanceCustodyPreservesOriginalCSRFState(t *testing.T) {
	codec, draft, spec, bearer, authority := issuanceCustodyFixture(t, true)
	s, _ := draft.Bindings()
	s.Continuation = csrfContinuation(t, s.Continuation)
	scope, _ := s.Continuation.DigestScope()
	code, _ := auth.NewOneTimeCode("123456")
	digest, err := codec.verifier.Digest(scope, code)
	if err != nil {
		t.Fatal(err)
	}
	s.Digest = digest.Storage()
	draft, err = otp.NewChallenge(s)
	if err != nil {
		t.Fatal(err)
	}
	command, err := codec.MapIssuanceSession(context.Background(), draft, spec, bearer, authority)
	if err != nil {
		t.Fatal(err)
	}
	wire := encodeIssuanceRecord(draft)
	requireClosedCSRFFrame(t, wire, func(data []byte) error { _, err := decodeIssuanceRecord(data); return err })
	for _, prefix := range []string{issuanceRecordPrefix, "identity-otp-issuance-record-v9\x00"} {
		altered := append([]byte(prefix), wire[len(csrfIssuanceRecordPrefix):]...)
		if _, err := decodeIssuanceRecord(altered); err == nil {
			t.Fatal("mixed issuance profile accepted")
		}
	}
	metadata, _ := command.Feature()
	restarted, _ := NewAttemptCodec(codecConfig())
	restored, err := restarted.restoreIssuance(metadata)
	if err != nil {
		t.Fatal("CSRF issuance failed restart", err)
	}
	g, _ := restored.challenge.Bindings()
	requireOriginalCSRF(t, s.Continuation, g.Continuation)
	if g.Policy != s.Policy || g.Digest != s.Digest || !g.IssuedAt.Equal(s.IssuedAt) || !g.ExpiresAt.Equal(s.ExpiresAt) || restored.authority != authority {
		t.Fatal("issuance intent changed")
	}
}

func TestSendCustodyPreservesOriginalCSRFState(t *testing.T) {
	codec, challenge, spec, bearer, authority := issuanceCustodyFixture(t, true)
	s, _ := challenge.Bindings()
	c := csrfContinuation(t, s.Continuation)
	b, _ := c.Bindings()
	eligibility := kernel.RecipientVerified
	if b.Scope.Purpose == otp.PurposeEmailVerification || b.Scope.Purpose == otp.PurposeEmailChange {
		eligibility = kernel.RecipientPendingOrVerified
	}
	recipient := kernel.RecipientRecord{
		Query:                kernel.RecipientQuery{TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, Kind: identity.IdentifierEmail, CanonicalValue: b.Scope.Destination.Value(), Eligibility: eligibility},
		User:                 identity.User{ID: spec.Binding.UserID, TenantID: spec.Binding.TenantID, Status: identity.StatusActive, Version: 7},
		Identifier:           identity.Identifier{ID: "email", UserID: spec.Binding.UserID, Kind: identity.IdentifierEmail, CanonicalValue: b.Scope.Destination.Value(), DisplayValue: "Original display", Verified: true, Primary: true, Version: 9},
		Verification:         identity.Verification{IdentifierID: "email", State: identity.VerificationVerified, VerifiedAt: s.IssuedAt, Version: 3},
		UserAuthorityVersion: 11, IdentifierAuthorityVersion: 12, CredentialAuthorityVersion: 13, ObservedAt: s.IssuedAt,
	}
	for _, selected := range []*kernel.RecipientRecord{nil, &recipient} {
		request := sendRequestRecord{continuation: c, policy: s.Policy, authority: authority, issuedAt: s.IssuedAt, expiresAt: s.ExpiresAt, recipient: selected}
		wire, err := encodeSendRequestRecord(request, spec.Binding)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeSendRequestRecord(wire, spec.Binding)
		if err != nil {
			t.Fatal(err)
		}
		requireClosedCSRFFrame(t, wire, func(data []byte) error { _, err := decodeSendRequestRecord(data, spec.Binding); return err })
		requireOriginalCSRF(t, c, got.continuation)
		if !reflect.DeepEqual(got.recipient, selected) || got.authority != authority || got.policy != s.Policy || !got.issuedAt.Equal(s.IssuedAt) || !got.expiresAt.Equal(s.ExpiresAt) {
			t.Fatal("send intent changed")
		}
		if selected != nil {
			s.Continuation = c
			scope, _ := c.DigestScope()
			code, _ := auth.NewOneTimeCode("123456")
			digest, err := codec.verifier.Digest(scope, code)
			if err != nil {
				t.Fatal(err)
			}
			s.Digest = digest.Storage()
			draft, err := otp.NewChallenge(s)
			if err != nil {
				t.Fatal(err)
			}
			command, err := codec.mapIssuance(context.Background(), draft, spec, bearer, authority, true, *selected)
			if err != nil {
				t.Fatal(err)
			}
			metadata, _ := command.Feature()
			restarted, _ := NewAttemptCodec(codecConfig())
			restored, err := restarted.restoreIssuance(metadata)
			if err != nil || !reflect.DeepEqual(restored.recipient, selected) {
				t.Fatal("recipient issuance lost original selection", err)
			}
			actual, _ := restored.challenge.Bindings()
			requireOriginalCSRF(t, c, actual.Continuation)
		}
	}
}

func csrfSessionCustodyFixture(t testing.TB) (otp.AttemptCommand, identity.FeatureCommandSpec, session.Session) {
	t.Helper()
	a, spec, original := sessionCustodyFixture(t)
	base, _ := original.Bindings()
	state, err := session.NewCSRFState(session.CSRFStateSpec{Binding: session.CSRFBinding{TenantID: base.TenantID, SessionID: base.SessionID, SessionVersion: base.Version}, KeyVersion: 7, Digest: [32]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSessionWithCSRF(base, state)
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := a.Bindings()
	cb, _ := ab.Continuation.Bindings()
	cb.Scope.AuthorizationBinding = [32]byte{}
	flow, err := otp.NewBoundSessionAuthorization(record)
	if err != nil {
		t.Fatal(err)
	}
	c, err := otp.NewContinuation(cb.Scope, flow, cb.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	code, _ := a.Code()
	attempt, err := issuer.PrepareForCommand(context.Background(), spec.Binding, spec.Operation, c, ab.Mode, ab.ExpectedVersion, code)
	if err != nil {
		t.Fatal(err)
	}
	return attempt, spec, record
}

func TestAttemptCustodyPreservesOriginalCSRFState(t *testing.T) {
	a, spec, original := csrfSessionCustodyFixture(t)
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	sealed, _ := issuer.SealForCommand(a)
	wire := encodeAttemptRecord(sealed)
	requireClosedCSRFFrame(t, wire, func(data []byte) error { _, err := decodeAttemptRecord(data, spec.Binding, spec.Operation); return err })
	for _, prefix := range []string{sessionRecordPrefix, "identity-otp-attempt-custody-v9\x00"} {
		altered := append([]byte(prefix), wire[len(csrfSessionRecordPrefix):]...)
		if _, err := decodeAttemptRecord(altered, spec.Binding, spec.Operation); err == nil {
			t.Fatal("mixed attempt profile accepted")
		}
	}
	// The CSRF extension immediately precedes the sealed signature.
	for _, zeroKey := range []bool{false, true} {
		altered := bytes.Clone(wire)
		start, end := len(wire)-68, len(wire)-64
		if !zeroKey {
			start, end = end, len(wire)-32
		}
		clear(altered[start:end])
		if _, err := decodeAttemptRecord(altered, spec.Binding, spec.Operation); err == nil {
			t.Fatal("zero CSRF key/digest accepted")
		}
	}
	for _, withAuthority := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "authority"}[withAuthority], func(t *testing.T) {
			codec, _ := NewAttemptCodec(codecConfig())
			var command identity.Command
			var plan kernel.OTPAttemptPlan
			var err error
			if withAuthority {
				expected := AttemptAuthority{Directory: kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: "tenant"}, GlobalVersion: 2, TenantVersion: 3}, UserAuthorityVersion: 4, IdentifierAuthorityVersion: 5, CredentialAuthorityVersion: 6, UserAuthorization: kernel.UserAuthorizationAdmission{Scope: authority.AuthorityScope{TenantID: "tenant", SubjectID: "user", PolicyNamespace: "users"}, Version: 9}}
				command, plan, err = codec.MapWithAuthority(context.Background(), a, 3, spec, expected)
			} else {
				command, plan, err = codec.Map(context.Background(), a, 3, spec)
			}
			if err != nil {
				t.Fatal(err)
			}
			restarted, _ := NewAttemptCodec(codecConfig())
			restored, err := restarted.restoreAttempt(command, plan)
			if err != nil {
				t.Fatal("CSRF-bearing original failed restart verification", err)
			}
			got, _ := restored.Bindings()
			c, _ := got.Continuation.Bindings()
			record, ok := c.Authorization.AuthenticatedSession()
			state, err := record.CSRFState().Bindings()
			want, _ := original.CSRFState().Bindings()
			if !ok || err != nil || state != want {
				t.Fatal("original CSRF state lost or replaced")
			}
			before, _ := a.Recovery()
			after, _ := restored.Recovery()
			if before != after {
				t.Fatal("restart replaced recovery identity")
			}
		})
	}
}
