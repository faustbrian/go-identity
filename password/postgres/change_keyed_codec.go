package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password"
	envelope "github.com/faustbrian/go-secret-envelope"
)

const maximumKeyedPasswordCustody = 131072

// Wire records are used only inside authenticated envelopes. Neither submitted
// bearer nor plaintext password is ever encoded. Original signed-proof and
// current-hash custody are sensitive and must not be exposed diagnostically.
type keyedPasswordChangeInput struct {
	Schema       uint8
	Binding      identity.CommandBinding
	Session      []identity.FeatureField
	Authority    identity.CredentialAuthorityRecord
	Hash         string
	Proof        []byte
	OccurredAt   time.Time
	RequestInput []identity.FeatureField
}

func (p *keyedPasswordChangePhase) inputAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if p == nil || p.service == nil || k.Namespace != p.service.config().RequestKeys.Namespace || k.Scope.RouteID != replacementOperation().OperationID || k.Scope.Method != "POST" || k.Feature.Contributor != p.Descriptor() || k.Feature.Operation != replacementOperation() || k.PolicyVersion != p.service.config().RequestKeys.Policy.PolicyVersion || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, password.ErrPasswordWork
	}
	// Explicit scalar provenance avoids the kernel binding's intentionally closed
	// serialization API. AAD includes every field, including configuration identity.
	frame, err := json.Marshal(struct {
		Namespace     string
		Scope         kernel.RequestKeyScope
		Admission     kernel.RequestKeyAdmission
		Feature       kernel.FeatureRegistration
		PolicyVersion uint64
		IntentDigest  [32]byte
		Configuration [32]byte
	}{k.Namespace, k.Scope, k.Admission, k.Feature, k.PolicyVersion, k.IntentDigest, p.service.identity})
	if err != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-password-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *keyedPasswordChangePhase) seal(ctx context.Context, aad envelope.Context, plain []byte) ([]byte, error) {
	if len(plain) == 0 || len(plain) > maximumKeyedPasswordCustody || ctx.Err() != nil {
		return nil, readerFailure(ctx)
	}
	encrypted, err := p.service.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.service.config().ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, readerFailure(ctx)
	}
	wire, err := encrypted.MarshalBinary()
	if err != nil || len(wire) > maximumKeyedPasswordCustody || ctx.Err() != nil {
		return nil, readerFailure(ctx)
	}
	return wire, nil
}

func (p *keyedPasswordChangePhase) open(ctx context.Context, aad envelope.Context, wire []byte) ([]byte, error) {
	if len(wire) == 0 || len(wire) > maximumKeyedPasswordCustody || ctx.Err() != nil {
		return nil, readerFailure(ctx)
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	plain, err := p.service.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil || ctx.Err() != nil || len(plain) == 0 || len(plain) > maximumKeyedPasswordCustody {
		clear(plain)
		return nil, readerFailure(ctx)
	}
	return plain, nil
}

func decodeKeyedPasswordJSON(plain []byte, target any) error {
	if len(plain) == 0 || len(plain) > maximumKeyedPasswordCustody {
		return password.ErrPasswordWork
	}
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return password.ErrPasswordWork
	}
	canonical, err := json.Marshal(target)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plain) {
		return password.ErrPasswordWork
	}
	return nil
}

func (p *keyedPasswordChangePhase) restoreInput(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) (keyedPasswordChangeInput, error) {
	bad := func(err error) (keyedPasswordChangeInput, error) { return keyedPasswordChangeInput{}, err }
	aad, err := p.inputAAD(k)
	if err != nil {
		return bad(err)
	}
	plain, err := p.open(ctx, aad, wire)
	if err != nil {
		return bad(err)
	}
	defer clear(plain)
	var input keyedPasswordChangeInput
	if decodeKeyedPasswordJSON(plain, &input) != nil || input.Schema != 1 || input.Binding.CommandID != k.Admission.CommandID || input.Binding.TenantID != k.Scope.TenantID || input.Binding.ActorID != k.Scope.ActorID || input.Binding.ActorKind != k.Scope.ActorKind || input.Binding.ValidateFor(k.Feature.Operation) != nil || input.OccurredAt.IsZero() {
		return bad(password.ErrPasswordWork)
	}
	r := p.request()
	intent, err := p.service.requestIntent(ctx, r)
	fields, ok := intent.Fields()
	stored, e := identity.NewRequestIntent(input.RequestInput)
	storedFields, storedOK := stored.Fields()
	currentWire, currentErr := json.Marshal(fields)
	originalWire, originalErr := json.Marshal(storedFields)
	if err != nil || e != nil || !ok || !storedOK || currentErr != nil || originalErr != nil || !bytes.Equal(currentWire, originalWire) {
		return bad(password.ErrPasswordWork)
	}
	if _, _, _, err := p.invocation(input, nil, identity.Command{}); err != nil {
		return bad(err)
	}
	return input, nil
}

func (p *keyedPasswordChangePhase) invocation(input keyedPasswordChangeInput, facts []risk.Signal, expected identity.Command) (*passwordChangePhase, session.Session, auth.SignedReauthenticationRecord, error) {
	r := p.request()
	original, err := sessionpg.OriginalSessionFromFields(input.Binding.TenantID, input.Binding.UserID, input.Session)
	if err != nil {
		return nil, session.Session{}, auth.SignedReauthenticationRecord{}, password.ErrPasswordWork
	}
	record, err := decodeReauthenticationRecord(r.Proof.Proof.ID, string(input.Binding.TenantID), string(input.Binding.UserID), input.Proof)
	if err != nil || record.Proof != r.Proof || record.Issuer != p.service.native.source.c.Issuer || record.Environment != p.service.native.source.c.Environment || record.CredentialID != input.Binding.RecordID || record.CredentialVersion != original.EffectiveCredentialVersion() || len(p.service.native.source.c.VerificationKeys[record.KeyID]) != ed25519.PublicKeySize {
		return nil, session.Session{}, auth.SignedReauthenticationRecord{}, password.ErrPasswordWork
	}
	// Bearer possession is checked even on terminal replay without renewing the
	// original session's lifetime or looking up a newer credential/material row.
	spec, _ := original.Bindings()
	token, err := session.ParseToken(r.Session.Token())
	matched := false
	if err == nil {
		for _, key := range p.service.native.source.c.LookupKeys {
			digest, e := token.Digest(key, string(input.Binding.TenantID))
			if e == nil && digest == spec.Lookup {
				matched = true
			}
		}
	}
	if !matched || input.Authority.Credential.Version != record.CredentialVersion {
		return nil, session.Session{}, auth.SignedReauthenticationRecord{}, identity.ForbiddenError{}
	}
	hash, err := primitive.ParseEncodedHash(input.Hash, p.service.native.source.repository.limits)
	if err != nil {
		return nil, session.Session{}, auth.SignedReauthenticationRecord{}, password.ErrPasswordWork
	}
	material, err := password.NewCredentialSnapshot(input.Authority, hash)
	if err != nil {
		return nil, session.Session{}, auth.SignedReauthenticationRecord{}, password.ErrPasswordWork
	}
	phase := &passwordChangePhase{owner: p, service: p.service.native, original: original, material: material, record: record, facts: facts, scope: risk.Context{Tenant: string(input.Binding.TenantID), Operation: risk.Action(replacementOperation().OperationID), Attempt: string(input.Binding.CommandID)}, use: p.service.proofUse(r, time.Time{}), intent: kernel.CredentialReplacementIntent{Credential: input.Authority.Credential, ExpectedUserVersion: input.Authority.User.Version, ExpectedAuthorityVersion: input.Authority.AuthorityVersion}, expected: expected}
	return phase, original, record, nil
}
