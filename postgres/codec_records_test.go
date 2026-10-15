package postgres

import (
	"bytes"
	"context"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

func recordGrant(t *testing.T, p capability.Payload, keyID string) capability.Grant {
	return recordGrantWithLimits(t, p, keyID, capability.DefaultLimits())
}

func recordGrantWithLimits(t *testing.T, p capability.Payload, keyID string, limits capability.Limits) capability.Grant {
	t.Helper()
	key := bytes.Repeat([]byte{1}, 32)
	signer, e := capability.NewHMACSHA256Signer(keyID, key)
	if e != nil {
		t.Fatal("synthetic signer")
	}
	verifier, e := capability.NewHMACSHA256Verifier(key)
	if e != nil {
		t.Fatal("synthetic verifier")
	}
	resolver, e := capability.NewKeySet([]capability.Key{{Issuer: p.Issuer, ID: keyID, Verifier: verifier}})
	if e != nil {
		t.Fatal("synthetic keys")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	token, e := capability.Issue(ctx, p, signer, limits)
	if e != nil {
		t.Fatal("synthetic issuance")
	}
	grant, e := capability.Verify(ctx, token, resolver, capability.VerifyOptions{Issuer: p.Issuer, Now: time.Unix(1000, 0), Limits: limits})
	if e != nil {
		t.Fatal("synthetic verification")
	}
	return grant
}

func TestRecordCommandCodecProofBounds(t *testing.T) {
	s, _ := recordLink(t, identity.AccountLinkExplicit, nil, nil, "proof-key").LinkAccount()
	p := s.Proof.Payload()
	// V2 independently bounds key-owner issuers to 256 bytes. Audience remains
	// admissible under broader parser limits and proves our narrower codec bound.
	p.Audiences = []string{string(bytes.Repeat([]byte{'a'}, 257))}
	limits := capability.DefaultLimits()
	limits.MaxFieldBytes = 512
	s.Proof = recordGrantWithLimits(t, p, "proof-key", limits)
	c, e := identity.NewAccountLinkCommand(s)
	if e != nil {
		t.Fatal("valid broad-profile grant rejected by core fixture")
	}
	if _, e := prepareClaim(c, [32]byte{1}); e == nil {
		t.Fatal("out-of-profile authenticated payload admitted")
	}
	if _, e := encodeCommandProof(capability.Grant{}, [32]byte{1}); e == nil {
		t.Fatal("zero authenticated proof accepted")
	}
}

func TestRecordCommandCodecCanonicalProofAndOptionalMethod(t *testing.T) {
	base := encodedRecord(t, recordLink(t, identity.AccountLinkExplicit, nil, nil, "proof-key"))
	reordered := encodedRecord(t, recordLink(t, identity.AccountLinkExplicit, nil, func(p *capability.Payload) {
		copy := map[string]string{}
		for k, v := range p.Caveats {
			copy[k] = v
		}
		p.Caveats = copy
	}, "proof-key"))
	if !bytes.Equal(base.canonical, reordered.canonical) {
		t.Fatal("proof caveat map ordering changed command meaning")
	}
	absent := encodedRecord(t, recordLink(t, identity.AccountLinkExplicit, func(s *identity.AccountLinkCommand) { s.Change.Method = nil }, nil, "proof-key"))
	if bytes.Contains(absent.canonical, []byte("method")) {
		t.Fatal("absent optional method encoded")
	}
	indefinite := encodedRecord(t, recordLink(t, identity.AccountLinkExplicit, func(s *identity.AccountLinkCommand) { s.Change.Method.ExpiresAt = time.Time{} }, nil, "proof-key"))
	if bytes.Contains(indefinite.canonical, []byte("expires_at")) {
		t.Fatal("absent credential expiry encoded")
	}
	admin := encodedRecord(t, recordLink(t, identity.AccountLinkAdministrative, nil, nil, "proof-key"))
	changed := encodedRecord(t, recordLink(t, identity.AccountLinkAdministrative, func(s *identity.AccountLinkCommand) { s.Change.Reason = "other-registered-reason" }, nil, "proof-key"))
	if bytes.Equal(admin.canonical, changed.canonical) {
		t.Fatal("administrative reason lost")
	}
	identifier := encodedRecord(t, recordIdentifier(t, identity.IdentifierAttach, nil, nil))
	other := encodedRecord(t, recordIdentifier(t, identity.IdentifierAttach, func(s *identity.IdentifierCommand) {
		s.Change.Kind = identity.IdentifierUsername
		s.Change.DisplayValue = ""
	}, nil))
	if bytes.Equal(identifier.canonical, other.canonical) || bytes.Contains(other.canonical, []byte("display_value")) {
		t.Fatal("kind or absent identifier display omitted incorrectly")
	}
}

func FuzzRecordCommandCodec(f *testing.F) {
	f.Add(uint8(0), uint8(1), true)
	f.Add(uint8(1), uint8(2), false)
	f.Add(uint8(2), uint8(3), true)
	f.Fuzz(func(t *testing.T, selector, n uint8, choice bool) {
		var c identity.Command
		switch selector % 3 {
		case 0:
			c = recordLink(t, identity.AccountLinkMode(1+n%3), func(s *identity.AccountLinkCommand) {
				s.Change.ExpectedUserVersion = 1 + uint64(n)
				s.Change.Method.Usable = choice
			}, nil, "proof-key")
		case 1:
			c = recordUnlink(t, func(s *identity.AccountUnlinkCommand) {
				s.Change.ExpectedUserVersion = 1 + uint64(n)
				s.RevokeProvider = choice
			}, nil)
		case 2:
			c = recordIdentifier(t, identity.IdentifierAction(1+n%5), func(s *identity.IdentifierCommand) { s.Change.ExpectedUserVersion = 1 + uint64(n) }, nil)
		}
		p := encodedRecord(t, c)
		q := encodedRecord(t, c)
		if !bytes.Equal(p.canonical, q.canonical) || len(p.canonical) > 1<<20 {
			t.Fatal("record encoding nondeterministic or unbounded")
		}
		rotated, e := prepareClaim(c, [32]byte{2})
		if e != nil || bytes.Equal(p.canonical, rotated.canonical) || !bytes.Equal(p.safeFields, rotated.safeFields) {
			t.Fatal("record key rotation corrupted safe scope")
		}
	})
}

func recordBinding(op, schema, record string) identity.CommandBinding {
	b := codecBinding()
	b.CommandID = "AAAAAAAAAAAAAAAAAAAABQ"
	b.ActorID = identity.ActorID(b.UserID)
	b.OperationID = op
	b.SchemaID = schema
	b.RecordID = record
	return b
}

func recordLink(t *testing.T, mode identity.AccountLinkMode, alter func(*identity.AccountLinkCommand), alterProof func(*capability.Payload), keyID string) identity.Command {
	t.Helper()
	b := recordBinding("identity.account.link-token", "identity-account", "account-a")
	b.LinkMode = mode
	s := identity.AccountLinkCommand{Binding: b, Change: identity.AccountLinkChange{Mode: mode, Account: identity.Account{ID: "account-a", TenantID: b.TenantID, UserID: b.UserID, Provider: "social", Issuer: "https://provider.example.test", Subject: "synthetic-provider-subject", Version: 1}, ExpectedUserVersion: 1, ExpectedSocialLinkVersion: 1, ExpectedCredentialVersion: 1}, SessionID: "session-a", SessionVersion: 1}
	s.Change.Method = &identity.LoginMethod{AccountID: s.Change.Account.ID, Credential: identity.CredentialRef{ID: "credential-a", TenantID: b.TenantID, UserID: b.UserID, Kind: identity.CredentialProvider, Owner: "identity/oauth", Version: 1}, Usable: true, ExpiresAt: time.Unix(2000, 1000)}
	if mode == identity.AccountLinkAdministrative {
		s.Change.Reason = "approved-recovery"
		s.Binding.ActorID = "administrator"
	}
	if mode == identity.AccountLinkImplicit {
		s.SessionID = ""
		s.SessionVersion = 0
		s.PreAuthTransactionID = "AAAAAAAAAAAAAAAAAAAABg"
		s.Binding.ActorKind = authorization.SubjectServiceAccount
		s.Binding.ActorID = "workload"
		s.Change.MatchedIdentifier = "identifier-a"
		s.Change.VerifiedCanonicalIdentifier = "synthetic@example.test"
		s.Change.ExpectedIdentifierAuthorityVersion = 1
		s.Change.ExpectedIdentifierVersion = 1
		s.Change.ExpectedVerificationVersion = 1
	}
	if alter != nil {
		alter(&s)
	}
	p, e := identity.BuildAccountLinkProofPayload(identity.AccountLinkProofSpec{Command: s, Issuer: "https://identity.example.test", Audience: "backend", ID: "proof-a", IssuedAt: time.Unix(900, 0), ExpiresAt: time.Unix(1100, 0)})
	if e != nil {
		t.Fatal("link proof shape")
	}
	if alterProof != nil {
		alterProof(&p)
	}
	s.Proof = recordGrant(t, p, keyID)
	c, e := identity.NewAccountLinkCommand(s)
	if e != nil {
		t.Fatal("typed link shape")
	}
	return c
}

func recordUnlink(t *testing.T, alter func(*identity.AccountUnlinkCommand), alterProof func(*capability.Payload)) identity.Command {
	t.Helper()
	b := recordBinding("identity.account.unlink", "identity-account", "account-a")
	s := identity.AccountUnlinkCommand{Binding: b, Change: identity.AccountUnlinkChange{TenantID: b.TenantID, UserID: b.UserID, AccountID: "account-a", ExpectedUserVersion: 1, ExpectedAccountVersion: 1, ExpectedSocialLinkVersion: 1, ExpectedCredentialVersion: 1}, SessionID: "session-a", SessionVersion: 1, RevokeProvider: true}
	if alter != nil {
		alter(&s)
	}
	p := capability.Payload{Version: 1, Issuer: "https://identity.example.test", Audiences: []string{"backend"}, Subject: string(b.UserID), Resource: string(s.Change.AccountID), Operation: b.OperationID, Tenant: string(b.TenantID), ID: "proof-a", MaxUses: 1, IssuedAt: time.Unix(900, 0), NotBefore: time.Unix(900, 0), ExpiresAt: time.Unix(1100, 0), Caveats: map[string]string{"command_id": string(s.Binding.CommandID), "session_id": s.SessionID, "session_version": strconv.FormatUint(s.SessionVersion, 10), "user_version": strconv.FormatUint(s.Change.ExpectedUserVersion, 10), "account_version": strconv.FormatUint(s.Change.ExpectedAccountVersion, 10), "social_link_version": strconv.FormatUint(s.Change.ExpectedSocialLinkVersion, 10), "credential_version": strconv.FormatUint(s.Change.ExpectedCredentialVersion, 10), "policy_version": strconv.FormatUint(s.Binding.PolicyVersion, 10), "revoke_provider": strconv.FormatBool(s.RevokeProvider)}}
	if alterProof != nil {
		alterProof(&p)
	}
	s.Proof = recordGrant(t, p, "proof-key")
	c, e := identity.NewAccountUnlinkCommand(s)
	if e != nil {
		t.Fatal("typed unlink shape")
	}
	return c
}

func recordIdentifier(t *testing.T, action identity.IdentifierAction, alter func(*identity.IdentifierCommand), alterProof func(*capability.Payload)) identity.Command {
	t.Helper()
	ops := map[identity.IdentifierAction]string{identity.IdentifierAttach: "identity.identifier.attach", identity.IdentifierVerify: "identity.identifier.verify", identity.IdentifierMakePrimary: "identity.identifier.make-primary", identity.IdentifierReplace: "identity.identifier.replace", identity.IdentifierRemove: "identity.identifier.remove"}
	b := recordBinding(ops[action], "identity-identifier", "identifier-a")
	s := identity.IdentifierCommand{Binding: b, Change: identity.IdentifierChange{TenantID: b.TenantID, UserID: b.UserID, Action: action, ID: "identifier-a", ExpectedUserVersion: 1, ExpectedAuthorityVersion: 1}, SessionID: "session-a", SessionVersion: 1}
	if action != identity.IdentifierAttach {
		s.Change.ExpectedIdentifierVersion = 1
		s.Change.ExpectedVerificationVersion = 1
	}
	if action == identity.IdentifierAttach || action == identity.IdentifierReplace {
		s.Change.Kind = identity.IdentifierEmail
		s.Change.CanonicalValue = "synthetic@example.test"
		s.Change.DisplayValue = "Synthetic@example.test"
	}
	if alter != nil {
		alter(&s)
	}
	p, e := identity.BuildIdentifierProofPayload(identity.IdentifierProofSpec{Command: s, Issuer: "https://identity.example.test", Audience: "backend", ID: "proof-a", IssuedAt: time.Unix(900, 0), ExpiresAt: time.Unix(1100, 0)})
	if e != nil {
		t.Fatal("identifier proof shape")
	}
	if alterProof != nil {
		alterProof(&p)
	}
	s.Proof = recordGrant(t, p, "proof-key")
	c, e := identity.NewIdentifierCommand(s)
	if e != nil {
		t.Fatal("typed identifier shape")
	}
	return c
}

func encodedRecord(t *testing.T, c identity.Command) claimRequest {
	t.Helper()
	q, e := prepareClaim(c, [32]byte{1})
	if e != nil {
		t.Fatal("record command not encoded")
	}
	return q
}

func TestRecordCommandCodecVariants(t *testing.T) {
	for _, mode := range []identity.AccountLinkMode{identity.AccountLinkExplicit, identity.AccountLinkImplicit, identity.AccountLinkAdministrative} {
		q := encodedRecord(t, recordLink(t, mode, nil, nil, "proof-key"))
		if !bytes.Contains(q.safeFields, []byte("record_id")) {
			t.Fatal("exact record omitted from safe collision fields")
		}
	}
	encodedRecord(t, recordUnlink(t, nil, nil))
	for _, action := range []identity.IdentifierAction{identity.IdentifierAttach, identity.IdentifierVerify, identity.IdentifierMakePrimary, identity.IdentifierReplace, identity.IdentifierRemove} {
		encodedRecord(t, recordIdentifier(t, action, nil, nil))
	}
}

func TestRecordCommandCodecBindsLinkIntent(t *testing.T) {
	base := encodedRecord(t, recordLink(t, identity.AccountLinkExplicit, nil, nil, "proof-key"))
	for _, alter := range []func(*identity.AccountLinkCommand){
		func(s *identity.AccountLinkCommand) { s.Change.Account.Subject = "changed-subject" }, func(s *identity.AccountLinkCommand) { s.Change.Account.Issuer = "https://other.example.test" }, func(s *identity.AccountLinkCommand) { s.Change.Account.Provider = "other" },
		func(s *identity.AccountLinkCommand) { s.Change.ExpectedUserVersion++ }, func(s *identity.AccountLinkCommand) { s.Change.ExpectedSocialLinkVersion++ }, func(s *identity.AccountLinkCommand) { s.Change.ExpectedCredentialVersion++ }, func(s *identity.AccountLinkCommand) { s.Change.ExpectedAccountVersion++; s.Change.Account.Version++ },
		func(s *identity.AccountLinkCommand) { s.SessionID = "session-b" }, func(s *identity.AccountLinkCommand) { s.SessionVersion++ }, func(s *identity.AccountLinkCommand) { s.Change.Method = nil }, func(s *identity.AccountLinkCommand) { s.Change.Method.Usable = false }, func(s *identity.AccountLinkCommand) { s.Change.Method.Credential.Version++ }, func(s *identity.AccountLinkCommand) { s.Change.Method.Credential.ID = "credential-b" }, func(s *identity.AccountLinkCommand) { s.Change.Method.Credential.Owner = "sso" }, func(s *identity.AccountLinkCommand) {
			s.Change.Method.ExpiresAt = s.Change.Method.ExpiresAt.Add(time.Microsecond)
		},
	} {
		other := encodedRecord(t, recordLink(t, identity.AccountLinkExplicit, alter, nil, "proof-key"))
		if bytes.Equal(base.canonical, other.canonical) {
			t.Fatal("link intent change not fingerprinted")
		}
	}
	for _, private := range []string{"synthetic-provider-subject", "synthetic@example.test"} {
		if bytes.Contains(base.canonical, []byte(private)) || bytes.Contains(base.safeFields, []byte(private)) {
			t.Fatal("private provider/identifier value leaked")
		}
	}
	implicit := encodedRecord(t, recordLink(t, identity.AccountLinkImplicit, nil, nil, "proof-key"))
	for _, alter := range []func(*identity.AccountLinkCommand){func(s *identity.AccountLinkCommand) { s.PreAuthTransactionID = "AAAAAAAAAAAAAAAAAAAABw" }, func(s *identity.AccountLinkCommand) { s.Change.MatchedIdentifier = "identifier-b" }, func(s *identity.AccountLinkCommand) { s.Change.VerifiedCanonicalIdentifier = "other@example.test" }, func(s *identity.AccountLinkCommand) { s.Change.ExpectedIdentifierAuthorityVersion++ }, func(s *identity.AccountLinkCommand) { s.Change.ExpectedIdentifierVersion++ }, func(s *identity.AccountLinkCommand) { s.Change.ExpectedVerificationVersion++ }} {
		q := encodedRecord(t, recordLink(t, identity.AccountLinkImplicit, alter, nil, "proof-key"))
		if bytes.Equal(implicit.canonical, q.canonical) {
			t.Fatal("implicit linking fence lost")
		}
	}
}

func TestRecordCommandCodecBindsProof(t *testing.T) {
	base := encodedRecord(t, recordLink(t, identity.AccountLinkExplicit, nil, nil, "proof-key"))
	for _, alter := range []func(*capability.Payload){func(p *capability.Payload) { p.ID = "proof-b" }, func(p *capability.Payload) { p.Issuer = "https://other.example.test" }, func(p *capability.Payload) { p.Audiences = []string{"other-backend"} }, func(p *capability.Payload) { p.IssuedAt = p.IssuedAt.Add(time.Second) }, func(p *capability.Payload) { p.NotBefore = p.NotBefore.Add(time.Second) }, func(p *capability.Payload) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) }, func(p *capability.Payload) { p.CorrelationID = "private-correlation" }} {
		q := encodedRecord(t, recordLink(t, identity.AccountLinkExplicit, nil, alter, "proof-key"))
		if bytes.Equal(base.canonical, q.canonical) {
			t.Fatal("changed authenticated proof was ignored")
		}
	}
	q := encodedRecord(t, recordLink(t, identity.AccountLinkExplicit, nil, nil, "other-proof-key"))
	if bytes.Equal(base.canonical, q.canonical) {
		t.Fatal("proof signing key ignored")
	}
}

func TestRecordCommandCodecBindsUnlinkAndIdentifiers(t *testing.T) {
	base := encodedRecord(t, recordUnlink(t, nil, nil))
	for _, alter := range []func(*identity.AccountUnlinkCommand){func(s *identity.AccountUnlinkCommand) { s.RevokeProvider = false }, func(s *identity.AccountUnlinkCommand) { s.Change.ExpectedUserVersion++ }, func(s *identity.AccountUnlinkCommand) { s.Change.ExpectedAccountVersion++ }, func(s *identity.AccountUnlinkCommand) { s.Change.ExpectedSocialLinkVersion++ }, func(s *identity.AccountUnlinkCommand) { s.Change.ExpectedCredentialVersion++ }, func(s *identity.AccountUnlinkCommand) { s.SessionVersion++ }, func(s *identity.AccountUnlinkCommand) { s.SessionID = "session-b" }} {
		q := encodedRecord(t, recordUnlink(t, alter, nil))
		if bytes.Equal(base.canonical, q.canonical) {
			t.Fatal("unlink choice/fence lost")
		}
	}
	base = encodedRecord(t, recordIdentifier(t, identity.IdentifierReplace, nil, nil))
	for _, alter := range []func(*identity.IdentifierCommand){func(s *identity.IdentifierCommand) { s.Change.CanonicalValue = "other@example.test" }, func(s *identity.IdentifierCommand) { s.Change.DisplayValue = "Other@example.test" }, func(s *identity.IdentifierCommand) { s.Change.ExpectedUserVersion++ }, func(s *identity.IdentifierCommand) { s.Change.ExpectedAuthorityVersion++ }, func(s *identity.IdentifierCommand) { s.Change.ExpectedIdentifierVersion++ }, func(s *identity.IdentifierCommand) { s.Change.ExpectedVerificationVersion++ }, func(s *identity.IdentifierCommand) { s.SessionID = "session-b" }, func(s *identity.IdentifierCommand) { s.SessionVersion++ }} {
		q := encodedRecord(t, recordIdentifier(t, identity.IdentifierReplace, alter, nil))
		if bytes.Equal(base.canonical, q.canonical) {
			t.Fatal("identifier choice/fence lost")
		}
	}
	if bytes.Contains(base.canonical, []byte("synthetic@example.test")) || bytes.Contains(base.canonical, []byte("Synthetic@example.test")) {
		t.Fatal("identifier plaintext in canonical command")
	}
	// Unkeyed intent digest is proof metadata, not persisted canonical safe data.
	s, _ := recordIdentifier(t, identity.IdentifierReplace, nil, nil).ChangeIdentifier()
	intent, _ := identity.IdentifierIntentDigest(s.Change)
	if bytes.Contains(base.canonical, []byte(hex.EncodeToString(intent[:]))) {
		t.Fatal("unkeyed proof intent digest leaked")
	}
}
