package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type keyedEmailInvocation struct {
	service *KeyedEmailManagementService
	request EmailManagementRequest
	resend  bool
}

// These aliases serialize only inside the authenticated existing request mapping.
// No bearer, raw CSRF or initiating key is included. The command fields retain
// their original counter instants/versions rather than recomputing today's ones.
type storedEmailPrevious kernel.ManagedEmailPrevious
type storedEmailCounter kernel.CommandCounterPlan
type keyedEmailInput struct {
	Schema               uint8
	Spec                 identity.FeatureCommandSpec
	Change               identity.IdentifierChange
	Comparison, Existing string
	Previous             storedEmailPrevious
	Counter              storedEmailCounter
	Proof                []byte
	RequestInput         []identity.FeatureField
	IssuedAt, ExpiresAt  time.Time
	TokenGeneration      uint64
}

func decodeKeyedEmailInput(plain []byte) (keyedEmailInput, error) {
	var input keyedEmailInput
	if decodeKeyedPasswordJSON(plain, &input) != nil || input.Schema != 1 || len(input.Proof) == 0 || len(input.Proof) > maximumReauthenticationRecordBytes || input.IssuedAt.IsZero() || !input.ExpiresAt.After(input.IssuedAt) || input.ExpiresAt.Sub(input.IssuedAt) > 24*time.Hour || input.TokenGeneration == 0 || input.Counter.PolicyVersion == 0 || input.Counter.Fingerprint == ([32]byte{}) {
		return keyedEmailInput{}, password.ErrPasswordWork
	}
	if _, err := identity.NewFeatureCommand(input.Spec); err != nil {
		return keyedEmailInput{}, password.ErrPasswordWork
	}
	if _, err := identity.NewRequestIntent(input.RequestInput); err != nil {
		return keyedEmailInput{}, password.ErrPasswordWork
	}
	return input, nil
}

var _ kernel.RequestKeyPreparationContributor = (*emailManagementPhase)(nil)

func (p *emailManagementPhase) requestAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if p == nil || p.keyed == nil || p.keyed.service == nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	s := p.keyed.service
	op := emailPrimaryOperation(s.native.primary.config.Action)
	if p.keyed.resend {
		op = managedResendOperation()
	}
	if k.Namespace != s.config().RequestKeys.Namespace || k.Scope.Method != "POST" || k.Scope.RouteID != op.OperationID || k.Feature.Contributor != p.Descriptor() || k.Feature.Operation != op || k.PolicyVersion != s.config().RequestKeys.Policy.PolicyVersion || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, password.ErrPasswordWork
	}
	frame, err := json.Marshal(struct {
		Namespace             string
		Scope                 kernel.RequestKeyScope
		Admission             kernel.RequestKeyAdmission
		Feature               kernel.FeatureRegistration
		Policy                uint64
		Intent, Configuration [32]byte
	}{k.Namespace, k.Scope, k.Admission, k.Feature, k.PolicyVersion, k.IntentDigest, s.profile})
	if err != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-email-request-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *emailManagementPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	aad, err := p.requestAAD(k)
	if err != nil {
		return nil, err
	}
	r := p.keyed.request
	r.Primary.CommandID = k.Admission.CommandID
	if !p.keyed.resend {
		id, err := identity.NewCommandID()
		if err != nil {
			return nil, password.ErrPasswordWork
		}
		r.Primary.AddressID = identity.IdentifierID(id)
	}
	prepared, err := p.service.prepareRequest(ctx, r, p.service.primary.config.Action, p.keyed.resend)
	if err != nil {
		return nil, err
	}
	spec, ok := prepared.command.Feature()
	if !ok || spec.Binding.ActorID != k.Scope.ActorID || spec.Binding.TenantID != k.Scope.TenantID || spec.Binding.ActorKind != k.Scope.ActorKind || spec.Binding.UserID != identity.UserID(k.Scope.ActorID) {
		return nil, identity.ForbiddenError{}
	}
	proof, err := encodeReauthenticationRecord(prepared.primary.custody().record)
	if p.service.primary.factor != nil {
		proof, err = json.Marshal(prepared.primary.custody().record)
	}
	if err != nil {
		return nil, err
	}
	defer clear(proof)
	fields, ok := intent.Fields()
	if !ok {
		return nil, password.ErrPasswordWork
	}
	input := keyedEmailInput{Schema: 1, Spec: spec, Change: prepared.intent.Change, Comparison: prepared.intent.ComparisonProfile, Existing: prepared.intent.ExistingCanonicalAddress, Previous: storedEmailPrevious(prepared.intent.Previous), Counter: storedEmailCounter(prepared.counter), Proof: proof, RequestInput: fields, IssuedAt: prepared.link.IssuedAt, ExpiresAt: prepared.link.ExpiresAt, TokenGeneration: prepared.link.Payload.Version}
	plain, err := json.Marshal(input)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	defer clear(plain)
	if len(plain) > maximumKeyedPasswordCustody-4096 {
		return nil, password.ErrPasswordWork
	}
	sealed, err := p.service.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.service.config().ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, readerFailure(ctx)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > maximumKeyedPasswordCustody {
		clear(wire)
		return nil, password.ErrPasswordWork
	}
	return wire, nil
}

func (p *emailManagementPhase) restoreRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) error {
	aad, err := p.requestAAD(k)
	if err != nil {
		return err
	}
	if len(wire) == 0 || len(wire) > maximumKeyedPasswordCustody {
		return password.ErrPasswordWork
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return password.ErrPasswordWork
	}
	plain, err := p.service.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil {
		return readerFailure(ctx)
	}
	input, err := decodeKeyedEmailInput(plain)
	if err != nil {
		return err
	}
	defer clear(input.Proof)
	b := input.Spec.Binding
	if b.CommandID != k.Admission.CommandID || b.TenantID != k.Scope.TenantID || b.ActorID != k.Scope.ActorID || b.ActorKind != k.Scope.ActorKind || b.UserID != identity.UserID(k.Scope.ActorID) || b.ValidateFor(k.Feature.Operation) != nil || input.Spec.Operation != k.Feature.Operation {
		return password.ErrPasswordWork
	}
	submitted, err := p.keyed.service.requestIntent(ctx, p.keyed.request, p.keyed.resend)
	current, ok := submitted.Fields()
	retained, e := identity.NewRequestIntent(input.RequestInput)
	stored, has := retained.Fields()
	currentWire, currentErr := json.Marshal(current)
	defer clear(currentWire)
	storedWire, storedErr := json.Marshal(stored)
	defer clear(storedWire)
	if err != nil || e != nil || !ok || !has || currentErr != nil || storedErr != nil || !bytes.Equal(currentWire, storedWire) {
		return password.ErrPasswordWork
	}
	request := p.keyed.request.Primary
	request.CommandID, request.AddressID = b.CommandID, identity.IdentifierID(b.RecordID)
	original, err := restoreEmailPrimary(ctx, p.service.primary, request, input.Spec.Fields, input.Proof)
	if err != nil {
		return err
	}
	link, err := p.service.managedVerificationIntent(emailManagementOutput{Spec: input.Spec, IssuedAt: input.IssuedAt, ExpiresAt: input.ExpiresAt, TokenGeneration: input.TokenGeneration})
	if err != nil {
		return err
	}
	if !link.IssuedAt.Equal(request.Proof.Proof.IssuedAt.UTC().Truncate(time.Second)) {
		return password.ErrPasswordWork
	}
	if err := p.service.checkFactorLinkDeadline(original, link); err != nil {
		return err
	}
	domain := kernel.EmailAttachmentIntent{Change: input.Change, ComparisonProfile: input.Comparison, ExistingCanonicalAddress: input.Existing, Previous: kernel.ManagedEmailPrevious(input.Previous)}
	fields, err := kernel.EmailAttachmentFields(domain)
	if err != nil {
		return err
	}
	if domain.Change.ID != link.IdentifierID || domain.Change.TenantID != b.TenantID || domain.Change.UserID != b.UserID || domain.ComparisonProfile != p.service.config().Domain.ComparisonProfile {
		return password.ErrPasswordWork
	}
	for _, expected := range fields {
		found := false
		expectedWire, _ := json.Marshal(expected)
		defer clear(expectedWire)
		for _, actual := range input.Spec.Fields {
			if actual.Name == expected.Name {
				actualWire, _ := json.Marshal(actual)
				found = bytes.Equal(expectedWire, actualWire)
				clear(actualWire)
				break
			}
		}
		if !found {
			return password.ErrPasswordWork
		}
	}
	command, err := identity.NewFeatureSessionCommand(input.Spec, request.Session)
	if err != nil {
		return err
	}
	counter := kernel.CommandCounterPlan(input.Counter)
	if p.service.config().Counters.ValidateCommandCounters(command, counter) != nil {
		return password.ErrPasswordWork
	}
	var factor uint64
	for _, field := range input.Spec.Fields {
		if field.Name == "email.management.factor-version" {
			factor = field.Value.Uint64
		}
	}
	if factor == 0 {
		return password.ErrPasswordWork
	}
	var family issuerpg.ManagedEmailSupersessionScope
	if p.service.config().ResendInterval != 0 {
		payload, err := p.service.payload(link)
		if err != nil {
			return err
		}
		family, err = issuerpg.ManagedEmailScopeFromPayload(payload)
		if err != nil {
			return err
		}
	}
	p.primary, p.intent, p.link, p.command, p.counter, p.factorVersion, p.family = original, domain, link, command, counter, factor, family
	return nil
}

// Authenticated retained input restores original possession, never fresh validity.
// Execution still fences live directory/session/credential/factor owners and
// consumes the proof atomically. Terminal replay is receipt metadata only.
func restoreEmailPrimary(ctx context.Context, source *EmailPrimarySource, request EmailPrimaryRequest, fields []identity.FeatureField, proof []byte) (EmailPrimaryAdmission, error) {
	var originalFields, primaryFields []identity.FeatureField
	values := map[string]identity.FeatureValue{}
	for _, field := range fields {
		values[field.Name] = field.Value
		if strings.HasPrefix(field.Name, "source-session.") {
			originalFields = append(originalFields, field)
		}
		if strings.HasPrefix(field.Name, "source-session.") || strings.HasPrefix(field.Name, "email.primary.") {
			primaryFields = append(primaryFields, field)
		}
	}
	user := identity.UserID(request.Caller.Request.Subject.ID)
	original, err := sessionpg.OriginalSessionFromFields(request.TenantID, user, originalFields)
	if err != nil {
		return EmailPrimaryAdmission{}, password.ErrPasswordWork
	}
	spec, err := original.Bindings()
	if err != nil {
		return EmailPrimaryAdmission{}, password.ErrPasswordWork
	}
	if _, err := emailPrimarySubject(source, request, user); err != nil {
		return EmailPrimaryAdmission{}, err
	}
	selectedTarget, present := values["email.primary.target-subject"]
	if request.TargetSubjectID != "" {
		if !present || selectedTarget.Kind != identity.FeatureText || selectedTarget.Text != string(request.TargetSubjectID) {
			return EmailPrimaryAdmission{}, identity.ForbiddenError{}
		}
	} else if present {
		return EmailPrimaryAdmission{}, identity.ForbiddenError{}
	}
	var record auth.SignedReauthenticationRecord
	var factor mfapg.EmailChangeFactorAdmission
	var digest [32]byte
	if source.factor != nil {
		factor, err = restoreEmailFactor(ctx, source, request.TenantID, user, original, values)
		if err != nil {
			return EmailPrimaryAdmission{}, err
		}
		record, err = factor.Original()
		wire, encodeErr := json.Marshal(record)
		defer clear(wire)
		if err != nil || encodeErr != nil || !bytes.Equal(wire, proof) || record.Proof != request.Proof {
			return EmailPrimaryAdmission{}, identity.ForbiddenError{}
		}
		digest, err = factor.Digest()
		if err != nil {
			return EmailPrimaryAdmission{}, err
		}
	} else {
		record, err = decodeReauthenticationRecord(request.Proof.Proof.ID, string(request.TenantID), string(user), proof)
		if err != nil || record.Proof != request.Proof || record.Issuer != source.source.c.Issuer || record.Environment != source.source.c.Environment || record.CredentialID != spec.Authentication.CredentialID || record.CredentialVersion != original.EffectiveCredentialVersion() || len(source.source.c.VerificationKeys[record.KeyID]) != ed25519.PublicKeySize {
			return EmailPrimaryAdmission{}, identity.ForbiddenError{}
		}
		frame, err := record.SigningBytes()
		defer clear(frame)
		if err != nil || !ed25519.Verify(source.source.c.VerificationKeys[record.KeyID], frame, record.Signature) {
			return EmailPrimaryAdmission{}, identity.ForbiddenError{}
		}
		digest = sha256.Sum256(proof)
	}
	d, id, age, cookie := values["email.primary.proof.digest"], values["email.primary.proof.id"], values["email.primary.maximum-age-nanos"], values["email.primary.cookie"]
	if d.Kind != identity.FeatureBytes || !bytes.Equal(d.Bytes, digest[:]) || id.Kind != identity.FeatureText || id.Text != string(record.Proof.Proof.ID) || age.Kind != identity.FeatureUint64 || age.Uint64 != uint64(source.config.MaximumAge) || cookie.Kind != identity.FeatureBool || cookie.Bool != (source.config.Transport == session.CredentialCookie) {
		return EmailPrimaryAdmission{}, password.ErrPasswordWork
	}
	token, err := session.ParseToken(request.Session.Token())
	matched := false
	if err == nil {
		for _, key := range source.source.c.LookupKeys {
			d, e := token.Digest(key, string(request.TenantID))
			if e == nil && d == spec.Lookup {
				matched = true
			}
		}
	}
	if !matched {
		return EmailPrimaryAdmission{}, identity.ForbiddenError{}
	}
	state := emailPrimaryCustody{source: source, request: request, original: original, record: record, use: auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: string(request.TenantID), Subject: string(user), Purpose: "identity.password.verify", Audience: source.config.Audience}, SessionID: spec.SessionID, SessionVersion: spec.Version, Action: source.config.Action, MaximumAge: source.config.MaximumAge}, fields: slices.Clone(primaryFields)}
	if source.factor != nil {
		state.factor = factor
		state.use.ProofUse.Purpose = "identity.email.change-request"
	}
	if source.config.Transport == session.CredentialCookie {
		csrf, err := original.CSRFState().Bindings()
		if err != nil {
			return EmailPrimaryAdmission{}, identity.ForbiddenError{}
		}
		for _, key := range source.config.CSRFKeys {
			if key.Version() == csrf.KeyVersion {
				state.csrfKey = key
				break
			}
		}
		if state.csrfKey.Version() == 0 || (passwordChangeCSRF{keys: source.config.CSRFKeys}).checkSession(original, request.CSRFToken) != nil {
			return EmailPrimaryAdmission{}, identity.ForbiddenError{}
		}
	}
	state.request.Caller = request.Caller.Clone()
	return EmailPrimaryAdmission{custody: func() emailPrimaryCustody { return state }}, nil
}
