package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"slices"
	"strings"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
)

const signinCustodyPrefix = "identity-otp-signin-custody-v1\x00"

func signinOperation(subject identity.FeatureSubjectRequirement) identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.signin", SchemaID: "identity-otp-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: subject}
}

// Only the owned public workflow calls this mapping after restoring Send's
// original encrypted custody and resolving current single-factor policy. It
// freezes the selected recipient and complete prospective session before the
// sole coordinator fingerprints the consuming command. This is not a grant.
func (c *AttemptCodec) mapSigninCommand(ctx context.Context, attempt otp.AttemptCommand, version uint32, spec identity.FeatureCommandSpec, cookie auth.BearerCredential, original issuanceCustody, record session.Session) (identity.Command, kernel.OTPAttemptPlan, error) {
	fail := func(err error) (identity.Command, kernel.OTPAttemptPlan, error) {
		return identity.Command{}, kernel.OTPAttemptPlan{}, err
	}
	if ctx == nil || c == nil || c.crypto == nil || len(spec.Fields) != 0 || original.recipient == nil {
		return fail(ErrInvalidCommand)
	}
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return fail(err)
	}
	ab, err := attempt.Bindings()
	if err != nil || original.authority.validate(spec.Binding) != nil || c.validateSigninSelection(spec, ab, version, original.challenge, *original.recipient, original.authority, record) != nil {
		return fail(ErrInvalidCommand)
	}
	fields, err := sessionpg.OTPSigninSessionFields(record)
	if err != nil {
		return fail(ErrInvalidCommand)
	}
	digest, err := signinSessionDigest(record)
	if err != nil {
		return fail(ErrInvalidCommand)
	}
	challenge := encodeIssuanceRecord(original.challenge)
	defer clear(challenge)
	plain := appendAuthorityText([]byte(signinCustodyPrefix), string(challenge))
	plain = appendSendRecipient(plain, *original.recipient)
	plain = append(plain, digest[:]...)
	defer clear(plain)
	if len(plain) > 8192 {
		return fail(ErrInvalidCommand)
	}
	aad, err := signinAAD(spec, version)
	if err != nil {
		return fail(ErrInvalidCommand)
	}
	sealed, err := c.crypto.Encrypt(bounded, envelope.EncryptRequest{Plaintext: plain, KeyReference: c.current, Context: aad})
	if err != nil {
		return fail(custodyFailure(bounded))
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > 8192 {
		return fail(ErrUnavailable)
	}
	spec.Fields = append(fields, identity.FeatureField{Name: "signin.custody", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: wire}})
	command, plan, err := c.MapPreAuthWithAuthority(bounded, attempt, version, spec, cookie, original.authority)
	if err != nil {
		return fail(err)
	}
	return command, plan, nil
}

func signinAAD(spec identity.FeatureCommandSpec, version uint32) (envelope.Context, error) {
	return commandCustodyAAD(spec, version, "identity-otp-signin-binding-v1\x00", "identity-otp-signin-v1")
}

// Session fields themselves are not covered by the existing OTP-attempt AAD.
// Commit their canonical complete projection, including CSRF and all epochs,
// inside separately authenticated private custody; never hash a raw bearer.
func signinSessionDigest(record session.Session) ([32]byte, error) {
	fields, err := sessionpg.OTPSigninSessionFields(record)
	if err != nil {
		return [32]byte{}, ErrInvalidCommand
	}
	slices.SortFunc(fields, func(a, b identity.FeatureField) int { return strings.Compare(a.Name, b.Name) })
	wire, err := json.Marshal(fields)
	if err != nil {
		return [32]byte{}, ErrInvalidCommand
	}
	defer clear(wire)
	return sha256.Sum256(append([]byte("identity-otp-signin-session-v1\x00"), wire...)), nil
}

// Restore authenticates only immutable original intent. Live primary policy,
// code comparison and consumption remain the existing native phase owners.
func (c *AttemptCodec) restoreSignin(command identity.Command, plan kernel.OTPAttemptPlan) (session.Session, kernel.RecipientRecord, error) {
	fail := func() (session.Session, kernel.RecipientRecord, error) {
		return session.Session{}, kernel.RecipientRecord{}, ErrInvalidCommand
	}
	spec, ok := command.Feature()
	if c == nil || c.crypto == nil || !ok || plan.Mode != kernel.OTPConsume || spec.Operation != signinOperation(spec.Operation.SubjectRequirement) {
		return fail()
	}
	var wire []byte
	for _, field := range spec.Fields {
		switch {
		case field.Name == "signin.custody":
			if wire != nil || field.Value.Kind != identity.FeatureBytes || len(field.Value.Bytes) == 0 || len(field.Value.Bytes) > 8192 {
				return fail()
			}
			wire = field.Value.Bytes
		case field.Name == "otp.attempt-custody", field.Name == "otp.digest-key-version", strings.HasPrefix(field.Name, "session.result."):
		default:
			return fail()
		}
	}
	if wire == nil {
		return fail()
	}
	// Matching the whole plan also authenticates the attempt's original code
	// commitment; neither a caller's version nor an independently decoded ID wins.
	attempt, err := c.restoreAttempt(command, plan)
	if err != nil {
		return fail()
	}
	ab, _ := attempt.Bindings()
	authority, err := c.restoreAuthority(spec)
	if err != nil {
		return fail()
	}
	record, err := sessionpg.OTPSigninSession(command)
	if err != nil {
		return fail()
	}
	aad, err := signinAAD(spec, plan.DigestKeyVersion)
	if err != nil {
		return fail()
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return fail()
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.maximumDuration)
	defer cancel()
	plain, err := c.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil {
		return fail()
	}
	defer clear(plain)
	if len(plain) > 8192 || !bytes.HasPrefix(plain, []byte(signinCustodyPrefix)) {
		return fail()
	}
	r := recordReader{data: plain[len(signinCustodyPrefix):], ok: true}
	challenge, err := decodeIssuanceRecord([]byte(r.text(8192)))
	if err != nil {
		return fail()
	}
	recipient, err := readSendRecipient(&r)
	if err != nil {
		return fail()
	}
	digest := r.take(sha256.Size)
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	want, err := signinSessionDigest(record)
	if err != nil || subtle.ConstantTimeCompare(digest, want[:]) != 1 || c.validateSigninSelection(spec, ab, plan.DigestKeyVersion, challenge, recipient, authority, record) != nil || ctx.Err() != nil {
		return fail()
	}
	return record, recipient, nil
}

func (c *AttemptCodec) validateSigninSelection(spec identity.FeatureCommandSpec, attempt otp.AttemptBindings, version uint32, original otp.Challenge, recipient kernel.RecipientRecord, authority AttemptAuthority, record session.Session) error {
	fail := func() error { return ErrInvalidCommand }
	issued, err := original.Bindings()
	if err != nil || version != issued.Digest.KeyVersion || issued.State != otp.ChallengeIssued || issued.Version != 1 || issued.UsedAttempts != 0 || issued.FailedAttempts != 0 || issued.Checks != 0 || attempt.CommandID != spec.Binding.CommandID || attempt.Mode != otp.AttemptModeConsume || spec.Operation != signinOperation(spec.Operation.SubjectRequirement) || spec.Binding.ValidateFor(spec.Operation) != nil {
		return fail()
	}
	b, err := issued.Continuation.Bindings()
	if err != nil || b.Scope.Purpose != otp.PurposeSignin || validateSendRecipient(recipient, b.Scope, spec.Binding) != nil || !bytes.Equal(appendSendContinuation(nil, issued.Continuation), appendSendContinuation(nil, attempt.Continuation)) {
		return fail()
	}
	preauth, ok := b.Authorization.PreAuthTransaction()
	if !ok {
		return fail()
	}
	flow, err := preauth.Bindings()
	if err != nil || spec.Binding.UserID == "" && spec.Binding.AnonymousFlowID != string(flow.Binding.ID) {
		return fail()
	}
	s, err := record.Bindings()
	if err != nil {
		return fail()
	}
	p, err := record.OTPAuthentication().Bindings()
	if err != nil || p.CommandID != spec.Binding.CommandID || string(p.SendCommandID) != b.Scope.ChallengeID || p.ChallengeID != b.Scope.ChallengeID || p.AttemptID != string(attempt.AttemptID) || p.IdentifierID != recipient.Identifier.ID || p.IdentifierKind != recipient.Identifier.Kind || p.IdentifierVersion != recipient.Identifier.Version || p.VerificationVersion != recipient.Verification.Version {
		return fail()
	}
	remember, err := s.Remember.Bindings()
	originalRemember, e := b.RememberPolicy.Bindings()
	if err != nil || e != nil || remember != originalRemember || s.TenantID != spec.Binding.TenantID || s.UserID != recipient.User.ID || s.Version != 1 || s.FamilyVersion != 1 || !s.IssuedAt.Equal(s.LastActivityAt) || !p.AuthenticatedAt.Equal(s.IssuedAt) || s.IssuedAt.Before(issued.IssuedAt) || s.IssuedAt.Before(flow.Binding.IssuedAt) {
		return fail()
	}
	until := issued.ExpiresAt
	if flow.Binding.ExpiresAt.Before(until) {
		until = flow.Binding.ExpiresAt
	}
	if !p.ValidUntil.Equal(until) || !s.IssuedAt.Before(until) {
		return fail()
	}
	a, err := s.Authority.Bindings()
	if err != nil || a.Organization.Present || a.Factor.Present || a.Passkey.Present || a.Global.Version != authority.Directory.GlobalVersion || a.Tenant.Version != authority.Directory.TenantVersion || a.User.Version != recipient.UserAuthorityVersion || a.Identifier.Version != recipient.IdentifierAuthorityVersion || a.Credential.Version != recipient.CredentialAuthorityVersion {
		return fail()
	}
	return nil
}
