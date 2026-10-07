package postgres

import (
	"context"
	"crypto/hmac"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope"
)

func issuanceOperation(subject identity.FeatureSubjectRequirement) identity.FeatureOperation {
	schema := "identity-otp-send"
	if subject == identity.FeatureSubjectAnonymousFlow {
		schema = "identity-otp-send-preauth"
	}
	return identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.send", SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: subject}
}

// MapIssuancePreAuth freezes a newly generated digest-only challenge, complete
// original pre-auth transaction and primary authority expectations into bounded
// authenticated encrypted command custody. The actual submitted cookie remains
// separate opaque root custody; no code, cookie or delivery payload enters the
// envelope. The caller supplies the original server-issued command binding and
// freshly prepared challenge; this method does not generate a code or issue it.
//
// Map once and preserve the returned command through retries and ambiguity.
// Remapping produces different intent and cannot replace original recovery.
// Mapping grants no live admission, permission, risk clearance or persistence.
// Those belong to the owning native transaction. Keys/crypto/deadline semantics
// match Map; nil/invalid input returns zero command and redacted ErrInvalidCommand.
// Cancellation is preserved. No SQL, provider, callback or goroutine runs.
func (c *AttemptCodec) MapIssuancePreAuth(ctx context.Context, challenge otp.Challenge, spec identity.FeatureCommandSpec, cookie auth.BearerCredential, original AttemptAuthority) (identity.Command, error) {
	return c.mapIssuance(ctx, challenge, spec, cookie, original, false)
}

// MapIssuanceSession uses the disjoint original authenticated-session variant
// of MapIssuancePreAuth. Complete original session, credential and timeline
// custody is frozen without renewal; actual token possession/current state are
// checked separately at live use. No submitted OTP code is manufactured.
func (c *AttemptCodec) MapIssuanceSession(ctx context.Context, challenge otp.Challenge, spec identity.FeatureCommandSpec, token auth.BearerCredential, original AttemptAuthority) (identity.Command, error) {
	return c.mapIssuance(ctx, challenge, spec, token, original, true)
}

type issuanceCustody struct {
	challenge otp.Challenge
	authority AttemptAuthority
	recipient *kernel.RecipientRecord
}

func validIssuance(challenge otp.Challenge, spec identity.FeatureCommandSpec) bool {
	s, err := challenge.Bindings()
	if err != nil || spec.Binding.ValidateFor(spec.Operation) != nil || spec.Operation != issuanceOperation(spec.Operation.SubjectRequirement) || s.State != otp.ChallengeIssued || s.Version != 1 || s.UsedAttempts != 0 || s.FailedAttempts != 0 || s.Checks != 0 {
		return false
	}
	b, err := s.Continuation.Bindings()
	p, _, policyErr := s.Policy.Bindings()
	if err != nil || policyErr != nil || p.TTL%1000 != 0 || p.ResendInterval%1000 != 0 || b.Scope.TenantID != string(spec.Binding.TenantID) || b.Scope.SubjectID != string(spec.Binding.UserID) || b.Scope.ChallengeID != spec.Binding.RecordID {
		return false
	}
	if original, ok := b.Authorization.PreAuthTransaction(); ok {
		r, err := original.Bindings()
		return err == nil && (spec.Binding.UserID != "" || spec.Binding.AnonymousFlowID == string(r.Binding.ID))
	}
	_, ok := b.Authorization.AuthenticatedSession()
	return ok && spec.Binding.UserID != ""
}

func (c *AttemptCodec) mapIssuance(ctx context.Context, challenge otp.Challenge, spec identity.FeatureCommandSpec, bearer auth.BearerCredential, original AttemptAuthority, authenticated bool, recipient ...kernel.RecipientRecord) (identity.Command, error) {
	bad := func(err error) (identity.Command, error) { return identity.Command{}, err }
	if ctx == nil || c == nil || c.crypto == nil || len(spec.Fields) > 126 {
		return bad(ErrInvalidCommand)
	}
	bounded, stop := context.WithTimeout(ctx, c.maximumDuration)
	defer stop()
	if err := bounded.Err(); err != nil {
		return bad(err)
	}
	if !validIssuance(challenge, spec) || original.validate(spec.Binding) != nil {
		return bad(ErrInvalidCommand)
	}
	if _, err := session.ParseToken(bearer.Token()); err != nil {
		return bad(ErrInvalidCommand)
	}
	s, _ := challenge.Bindings()
	b, _ := s.Continuation.Bindings()
	_, sessionBound := b.Authorization.AuthenticatedSession()
	if sessionBound != authenticated {
		return bad(ErrInvalidCommand)
	}
	scope, _ := s.Continuation.DigestScope()
	scopeDigest, err := c.verifier.ScopeDigest(scope, s.Digest.KeyVersion)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	fields := make([]identity.FeatureField, 0, len(spec.Fields)+2)
	for _, f := range spec.Fields {
		if otpField(f.Name) {
			return bad(ErrInvalidCommand)
		}
		fields = append(fields, f)
	}
	aad, err := issuanceAAD(spec, s.Digest.KeyVersion)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	record := encodeIssuanceRecord(challenge)
	if len(recipient) > 1 {
		clear(record)
		return bad(ErrInvalidCommand)
	}
	if len(recipient) == 1 {
		if validateSendRecipient(recipient[0], b.Scope, spec.Binding) != nil {
			clear(record)
			return bad(ErrInvalidCommand)
		}
		selected := appendSendRecipient(nil, recipient[0])
		wrapped := appendAuthorityText([]byte(issuanceRecipientRecordPrefix), string(record))
		clear(record)
		record = appendAuthorityText(wrapped, string(selected))
		clear(selected)
	}
	// Preserve the original key-dependent scope commitment inside authenticated
	// ciphertext. A retained version number alone cannot detect changed key
	// material or prevent later persistence from reinterpreting its scope.
	record = append(record, scopeDigest.Value[:]...)
	plain := encodeAuthorityRecord(record, original)
	clear(record)
	defer clear(plain)
	if len(plain) > 8192 {
		return bad(ErrInvalidCommand)
	}
	encrypted, err := c.crypto.Encrypt(bounded, envelope.EncryptRequest{Plaintext: plain, KeyReference: c.current, Context: aad})
	if err != nil {
		return bad(custodyFailure(bounded))
	}
	wire, err := encrypted.MarshalBinary()
	if err != nil || len(wire) > 8192 {
		return bad(ErrUnavailable)
	}
	fields = append(fields, identity.FeatureField{Name: "otp.issue-custody", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: wire}}, identity.FeatureField{Name: "otp.digest-key-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(s.Digest.KeyVersion)}})
	spec.Fields = fields
	var command identity.Command
	if authenticated {
		command, err = identity.NewFeatureSessionCommand(spec, bearer)
	} else {
		command, err = identity.NewFeaturePreAuthCommand(spec, bearer)
	}
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	if err := bounded.Err(); err != nil {
		return bad(err)
	}
	return command, nil
}

func issuanceAAD(spec identity.FeatureCommandSpec, version uint32) (envelope.Context, error) {
	return commandCustodyAAD(spec, version, "identity-otp-issuance-envelope-binding-v1\x00", "identity-otp-issuance-custody-v1")
}

// Restoration authenticates the closed code-free issuance profile only. It
// cannot become attempt authority or recover a submitted bearer. Native live
// admission must still use the separately borrowed original bearer.
func (c *AttemptCodec) restoreIssuance(spec identity.FeatureCommandSpec) (issuanceCustody, error) {
	return c.restoreIssuanceContext(context.Background(), spec)
}

func (c *AttemptCodec) restoreIssuanceContext(parent context.Context, spec identity.FeatureCommandSpec) (issuanceCustody, error) {
	bad := func() (issuanceCustody, error) { return issuanceCustody{}, ErrInvalidCommand }
	if parent == nil || c == nil || c.crypto == nil || len(spec.Fields) > 128 {
		return bad()
	}
	if err := parent.Err(); err != nil {
		return issuanceCustody{}, err
	}
	var wire []byte
	var version uint32
	for _, f := range spec.Fields {
		if !otpField(f.Name) {
			continue
		}
		switch f.Name {
		case "otp.issue-custody":
			if wire != nil || f.Value.Kind != identity.FeatureBytes || len(f.Value.Bytes) == 0 || len(f.Value.Bytes) > 8192 {
				return bad()
			}
			wire = f.Value.Bytes
		case "otp.digest-key-version":
			if version != 0 || f.Value.Kind != identity.FeatureUint64 || f.Value.Uint64 == 0 || f.Value.Uint64 > uint64(^uint32(0)) {
				return bad()
			}
			version = uint32(f.Value.Uint64)
		default:
			return bad()
		}
	}
	if wire == nil || version == 0 {
		return bad()
	}
	aad, err := issuanceAAD(spec, version)
	if err != nil {
		return bad()
	}
	encrypted, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return bad()
	}
	ctx, stop := context.WithTimeout(parent, c.maximumDuration)
	defer stop()
	plain, err := c.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: encrypted, Context: aad})
	if err != nil {
		return bad()
	}
	defer clear(plain)
	record, authority, err := decodeBoundAuthorityRecord(plain, spec.Binding, true)
	if err != nil || authority == nil {
		return bad()
	}
	if len(record) < 32 {
		return bad()
	}
	committedScope := record[len(record)-32:]
	issuance, recipient, err := unwrapRecipientIssuance(record[:len(record)-32])
	if err != nil {
		return bad()
	}
	challenge, err := decodeIssuanceRecord(issuance)
	if err != nil || !validIssuance(challenge, spec) {
		return bad()
	}
	s, _ := challenge.Bindings()
	if recipient != nil {
		b, _ := s.Continuation.Bindings()
		if validateSendRecipient(*recipient, b.Scope, spec.Binding) != nil {
			return bad()
		}
	}
	scope, _ := s.Continuation.DigestScope()
	if s.Digest.KeyVersion != version {
		return bad()
	}
	scopeDigest, err := c.verifier.ScopeDigest(scope, version)
	if err != nil || !hmac.Equal(scopeDigest.Value[:], committedScope) || ctx.Err() != nil {
		return bad()
	}
	return issuanceCustody{challenge: challenge, authority: *authority, recipient: recipient}, nil
}

// Possession is checked against original frozen commitments, never against
// caller digests or adopted primary projections. This is only a local boundary:
// the native Work must still lock current primary authority/flow/shared abuse
// and recheck all time bounds after downstream waits before storing issuance.
func (p *Contributor) authenticateIssuance(ctx context.Context, command identity.Command) (issuanceCustody, nativeFlow, error) {
	bad := func(err error) (issuanceCustody, nativeFlow, error) { return issuanceCustody{}, nativeFlow{}, err }
	if ctx == nil || p == nil || p.codec == nil {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	spec, ok := command.Feature()
	if !ok {
		return bad(ErrInvalidCommand)
	}
	if _, present := command.OneTimeCode(); present {
		return bad(ErrInvalidCommand)
	}
	custody, err := p.codec.restoreIssuanceContext(ctx, spec)
	if err != nil {
		if ctx.Err() != nil {
			return bad(ctx.Err())
		}
		return bad(ErrInvalidCommand)
	}
	a := custody.authority
	s, _ := custody.challenge.Bindings()
	flow, err := p.authenticateSendFlow(ctx, command, s.Continuation, a)
	if err != nil {
		return bad(err)
	}
	return custody, flow, nil
}

// Original bearer possession is shared by code-free requests and generated
// issuance. Neither path adopts newer primary state or grants live admission.
func (p *Contributor) authenticateSendFlow(ctx context.Context, command identity.Command, continuation otp.Continuation, a AttemptAuthority) (nativeFlow, error) {
	bad := func(err error) (nativeFlow, error) { return nativeFlow{}, err }
	if ctx == nil || p == nil || p.codec == nil {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	spec, ok := command.Feature()
	if !ok {
		return bad(ErrInvalidCommand)
	}
	if a.Directory.Query.GlobalAuthorityID != p.global || spec.Binding.UserID != "" && a.UserAuthorization.Scope.PolicyNamespace != p.namespace {
		return bad(ErrInvalidCommand)
	}
	b, err := continuation.Bindings()
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	var flow nativeFlow
	if original, sessionBound := b.Authorization.AuthenticatedSession(); sessionBound {
		bearer, present := command.SessionToken()
		if !present || p.session == nil || p.sessionAuthority(original, spec.Binding, a) != nil {
			return bad(ErrInvalidCommand)
		}
		projection, _ := original.Bindings()
		key, retained := p.session.keys[projection.Lookup.KeyVersion]
		if !retained {
			return bad(ErrInvalidCommand)
		}
		token, err := session.ParseToken(bearer.Token())
		if err != nil {
			return bad(ErrInvalidCommand)
		}
		actual, err := token.Digest(key, string(projection.TenantID))
		if err != nil || actual.KeyVersion != projection.Lookup.KeyVersion || !hmac.Equal(actual.Sum[:], projection.Lookup.Sum[:]) {
			return bad(ErrInvalidCommand)
		}
		flow.session = original
	} else {
		original, bound := b.Authorization.PreAuthTransaction()
		bearer, present := command.PreAuthCookie()
		if !bound || !present || p.preauth == nil {
			return bad(ErrInvalidCommand)
		}
		projection, _ := original.Bindings()
		key, retained := p.preauth.keys[projection.Cookie.KeyVersion]
		if !retained {
			return bad(ErrInvalidCommand)
		}
		token, err := session.ParseToken(bearer.Token())
		if err != nil {
			return bad(ErrInvalidCommand)
		}
		actual, err := token.PreAuthDigest(key, projection.Binding)
		if err != nil || actual.KeyVersion != projection.Cookie.KeyVersion || !hmac.Equal(actual.Sum[:], projection.Cookie.Sum[:]) {
			return bad(ErrInvalidCommand)
		}
		flow.preauth = original
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	return flow, nil
}
