package postgres

import (
	authentication "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	"time"
)

// The native issue vocabulary is closed and scalar. It deliberately does not
// smuggle an arbitrary JSON record, raw bearer or opaque proof through the
// shared codec. Exact nanosecond times use canonical UTC text because the
// shared FeatureTime profile is microsecond-only.
func mapIssue(issue session.IssueCommandSpec) (identity.Command, error) {
	return mapSessionRecord(issue.Binding, session.IssueOperation(), issue.Session)
}

// Both native operations bind the same complete immutable record, without an
// opaque JSON escape or a second authority vocabulary. Issuance and revocation
// apply their own version, purpose and temporal requirements after decoding.
func mapSessionRecord(b identity.CommandBinding, operation identity.FeatureOperation, record session.Session) (identity.Command, error) {
	fields, err := sessionRecordFields(record, false)
	if err != nil {
		return identity.Command{}, err
	}
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: operation, Fields: fields})
}

func sessionRecordFields(record session.Session, otp bool) ([]identity.FeatureField, error) {
	s, err := record.Bindings()
	if err != nil || (!otp && s.Authentication.Kind != session.AuthenticationVerified) || (otp && s.Authentication.Kind != session.AuthenticationOTP) {
		return nil, session.ErrInvalidSessionCommand
	}
	remember, _ := s.Remember.Bindings()
	authority, _ := s.Authority.Bindings()
	fields := make([]identity.FeatureField, 0, 64)
	add := func(name string, value identity.FeatureValue) {
		fields = append(fields, identity.FeatureField{Name: name, Value: value})
	}
	text := func(name, value string) { add(name, identity.FeatureValue{Kind: identity.FeatureText, Text: value}) }
	number := func(name string, value uint64) {
		add(name, identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value})
	}
	duration := func(name string, value time.Duration) {
		add(name, identity.FeatureValue{Kind: identity.FeatureInt64, Int64: int64(value)})
	}
	instant := func(name string, value time.Time) { text(name, value.UTC().Format(storedTimeLayout)) }
	binding := func(name string, value session.AuthorityBinding) {
		text(name+".key", value.ScopeKey)
		number(name+".version", value.Version)
	}
	optional := func(name string, value session.OptionalAuthorityBinding) {
		add(name+".present", identity.FeatureValue{Kind: identity.FeatureBool, Bool: value.Present})
		binding(name, value.Binding)
	}
	text("session.id", s.SessionID)
	text("family.id", s.FamilyID)
	text("audience", s.Audience)
	number("session.version", s.Version)
	number("family.version", s.FamilyVersion)
	number("remember.choice", uint64(remember.Choice))
	duration("remember.absolute", remember.AbsoluteTTL)
	duration("remember.idle", remember.IdleTTL)
	duration("remember.refresh", remember.RefreshAfter)
	duration("remember.fresh", remember.FreshFor)
	number("lookup.version", uint64(s.Lookup.KeyVersion))
	add("lookup.digest", identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: s.Lookup.Sum[:]})
	a := s.Authentication
	number("authentication.kind", uint64(a.Kind))
	if otp {
		p, err := record.OTPAuthentication().Bindings()
		if err != nil {
			return nil, session.ErrInvalidSessionCommand
		}
		text("tenant.id", string(s.TenantID))
		text("user.id", string(s.UserID))
		text("otp.command", string(p.CommandID))
		text("otp.send", string(p.SendCommandID))
		text("otp.challenge", p.ChallengeID)
		text("otp.attempt", p.AttemptID)
		text("otp.identifier", string(p.IdentifierID))
		text("otp.kind", string(p.IdentifierKind))
		number("otp.identifier-version", p.IdentifierVersion)
		number("otp.verification-version", p.VerificationVersion)
		instant("otp.authenticated", p.AuthenticatedAt)
		instant("otp.valid-until", p.ValidUntil)
	} else {
		number("authentication.version", a.ProofVersion)
		text("credential.id", a.CredentialID)
		number("credential.version", a.CredentialVersion)
		p := a.Proof
		text("proof.id", string(p.ID))
		text("proof.tenant", p.Tenant)
		text("proof.subject", p.Subject)
		text("proof.method", p.Method)
		text("proof.purpose", string(p.Purpose))
		text("proof.audience", p.Audience)
		number("proof.assurance", uint64(p.Assurance))
		instant("proof.issued", p.IssuedAt)
		instant("proof.expires", p.ExpiresAt)
	}
	instant("session.issued", s.IssuedAt)
	instant("session.activity", s.LastActivityAt)
	binding("authority.global", authority.Global)
	binding("authority.tenant", authority.Tenant)
	binding("authority.user", authority.User)
	binding("authority.identifier", authority.Identifier)
	binding("authority.credential", authority.Credential)
	binding("authority.family", authority.SessionFamily)
	binding("authority.session", authority.Session)
	binding("authority.authorization", authority.Authorization)
	text("authority.organization.id", authority.ActiveOrganizationID)
	optional("authority.organization", authority.Organization)
	optional("authority.factor", authority.Factor)
	optional("authority.passkey", authority.Passkey)
	fields = appendCSRFFields(fields, "", record)
	return fields, nil
}

// Reconstruction is structural only. Private proof provenance, current owner
// checks, original one-time use and transaction ownership are separate phases.
func nativeIssue(command identity.Command) (session.SessionCommand, error) {
	b, record, err := nativeSessionRecord(command, session.IssueOperation())
	if err != nil {
		return session.SessionCommand{}, err
	}
	return session.NewIssueCommand(b, record)
}

func nativeSessionRecord(command identity.Command, operation identity.FeatureOperation) (identity.CommandBinding, session.Session, error) {
	fail := func() (identity.CommandBinding, session.Session, error) {
		return identity.CommandBinding{}, session.Session{}, session.ErrInvalidSessionCommand
	}
	projection, ok := command.Feature()
	if !ok || projection.Operation != operation {
		return fail()
	}
	values := make(map[string]identity.FeatureValue, len(projection.Fields))
	for _, field := range projection.Fields {
		values[field.Name] = field.Value
	}
	record, err := sessionRecordFromFields(projection.Binding, values, false)
	if err != nil {
		return fail()
	}
	return projection.Binding, record, nil
}

func sessionRecordFromFields(b identity.CommandBinding, values map[string]identity.FeatureValue, otp bool) (session.Session, error) {
	fail := func() (session.Session, error) { return session.Session{}, session.ErrInvalidSessionCommand }
	valid := true
	take := func(name string, kind identity.FeatureKind) identity.FeatureValue {
		v, exists := values[name]
		delete(values, name)
		if !exists || v.Kind != kind {
			valid = false
		}
		return v
	}
	text := func(name string) string { return take(name, identity.FeatureText).Text }
	number := func(name string) uint64 { return take(name, identity.FeatureUint64).Uint64 }
	small := func(name string, maximum uint64) uint64 {
		n := number(name)
		if n > maximum {
			valid = false
		}
		return n
	}
	duration := func(name string) time.Duration { return time.Duration(take(name, identity.FeatureInt64).Int64) }
	instant := func(name string) time.Time {
		raw := text(name)
		result, err := time.Parse(storedTimeLayout, raw)
		if err != nil || result.UTC().Format(storedTimeLayout) != raw {
			valid = false
		}
		return result
	}
	binding := func(name string) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: text(name + ".key"), Version: number(name + ".version")}
	}
	optional := func(name string) session.OptionalAuthorityBinding {
		return session.OptionalAuthorityBinding{Present: take(name+".present", identity.FeatureBool).Bool, Binding: binding(name)}
	}
	s := session.SessionSpec{TenantID: b.TenantID, UserID: b.UserID}
	s.SessionID, s.FamilyID, s.Audience = text("session.id"), text("family.id"), text("audience")
	s.Version, s.FamilyVersion = number("session.version"), number("family.version")
	remember := session.RememberPolicySpec{Choice: session.RememberChoice(small("remember.choice", 255)), AbsoluteTTL: duration("remember.absolute"), IdleTTL: duration("remember.idle"), RefreshAfter: duration("remember.refresh"), FreshFor: duration("remember.fresh")}
	s.Lookup.KeyVersion = uint32(small("lookup.version", uint64(^uint32(0))))
	digest := take("lookup.digest", identity.FeatureBytes).Bytes
	if len(digest) != len(s.Lookup.Sum) {
		valid = false
	} else {
		copy(s.Lookup.Sum[:], digest)
	}
	s.Authentication.Kind = session.AuthenticationKind(small("authentication.kind", 255))
	var metadata session.OTPAuthentication
	if otp {
		s.TenantID, s.UserID = identity.TenantID(text("tenant.id")), identity.UserID(text("user.id"))
		p := session.OTPAuthenticationSpec{CommandID: identity.CommandID(text("otp.command")), SendCommandID: identity.CommandID(text("otp.send")), ChallengeID: text("otp.challenge"), AttemptID: text("otp.attempt"), IdentifierID: identity.IdentifierID(text("otp.identifier")), IdentifierKind: identity.IdentifierKind(text("otp.kind")), IdentifierVersion: number("otp.identifier-version"), VerificationVersion: number("otp.verification-version"), AuthenticatedAt: instant("otp.authenticated"), ValidUntil: instant("otp.valid-until")}
		if s.TenantID != b.TenantID || (b.UserID != "" && s.UserID != b.UserID) || p.CommandID != b.CommandID {
			return fail()
		}
		var err error
		metadata, err = session.NewOTPAuthentication(p)
		if err != nil {
			return fail()
		}
	} else {
		s.Authentication.ProofVersion = number("authentication.version")
		s.Authentication.CredentialID, s.Authentication.CredentialVersion = text("credential.id"), number("credential.version")
		p := authentication.Proof{ID: authentication.ProofID(text("proof.id")), Tenant: text("proof.tenant"), Subject: text("proof.subject"), Method: text("proof.method"), Purpose: authentication.Purpose(text("proof.purpose")), Audience: text("proof.audience"), Assurance: authentication.Assurance(small("proof.assurance", 255)), IssuedAt: instant("proof.issued"), ExpiresAt: instant("proof.expires")}
		s.Authentication.Proof = p
	}
	s.IssuedAt, s.LastActivityAt = instant("session.issued"), instant("session.activity")
	authority := session.AuthoritySnapshotSpec{Global: binding("authority.global"), Tenant: binding("authority.tenant"), User: binding("authority.user"), Identifier: binding("authority.identifier"), Credential: binding("authority.credential"), SessionFamily: binding("authority.family"), Session: binding("authority.session"), Authorization: binding("authority.authorization"), ActiveOrganizationID: text("authority.organization.id"), Organization: optional("authority.organization"), Factor: optional("authority.factor"), Passkey: optional("authority.passkey")}
	if !valid || (!otp && s.Authentication.Kind != session.AuthenticationVerified) || (otp && s.Authentication.Kind != session.AuthenticationOTP) {
		return fail()
	}
	var err error
	s.Remember, err = session.NewRememberPolicy(remember)
	if err != nil {
		return fail()
	}
	s.Authority, err = session.NewAuthoritySnapshot(authority)
	if err != nil {
		return fail()
	}
	record, err := sessionFromCSRFFieldsWithOTP(values, "", s, metadata)
	if err != nil || len(values) != 0 {
		return fail()
	}
	return record, nil
}
