package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/url"
	"reflect"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/jackc/pgx/v5"
)

// This is the non-exchange binding retained after secret erasure. In particular,
// it must never contain the PKCE verifier or the canonical callback-state proof.
type rpStartBinding struct {
	Schema                  uint8
	Input                   rpStartInput
	Provider                oauth.ProviderProfile
	CallbackCommandID       identity.CommandID
	AccountRecordID         string
	State, Nonce, Challenge string
	StateKeyVersion         uint32
	StateReplayKeyVersion   uint32
	StateDigest             [32]byte
	PKCEKeyVersion          uint32
	PKCECommitment          [32]byte
	IssuedAt, ExpiresAt     time.Time
}

type rpStartOutput struct {
	Schema                                                              uint8
	Generation                                                          uint64
	Binding                                                             rpStartBinding
	BindingCiphertext, PKCECiphertext, StateProofCiphertext, Checkpoint []byte
	Plan                                                                rpStoredIssuancePlan
}

// Only this explicit projection may encode issuer metadata, inside the native
// encrypted output. Public CapabilityPlan deliberately refuses serialization.
type rpStoredGrant kernel.CapabilityPlan

// Retain original issuer metadata, not its bearer or another consumption owner.
// The kernel journal and capability participant verify this exact metadata on
// retry. Keeping it beside the encrypted binding lets terminal replay erase all
// exchange secrets without reconstructing or renewing a grant.
type rpStoredTransaction struct {
	Binding rpStartBinding
	State   rpStoredGrant
}

type rpStoredIssuancePlan struct {
	Contributor kernel.ContributorDescriptor
	Grants      []rpStoredGrant
}

func (p rpStoredIssuancePlan) native() kernel.CapabilityIssuancePlan {
	out := kernel.CapabilityIssuancePlan{Contributor: p.Contributor, Grants: make([]kernel.CapabilityPlan, len(p.Grants))}
	for i, g := range p.Grants {
		out.Grants[i] = kernel.CapabilityPlan(g)
	}
	return out
}

func rpQuotedSchema(schema string) string { return pgx.Identifier{schema}.Sanitize() }

// Browser state is an opaque lookup secret, not the canonical capability proof.
// Version and length framing keep this named-key domain distinct from grants,
// PKCE commitments and original-key intent even when input bytes coincide.
func rpStateDigest(key [32]byte, version uint32, tenant identity.TenantID, provider string, state []byte) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity.oauth.rp.state-lookup.v1\x00"))
	_, _ = mac.Write(binary.BigEndian.AppendUint32(nil, version))
	for _, v := range [][]byte{[]byte(tenant), []byte(provider), state} {
		_, _ = mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(v))))
		_, _ = mac.Write(v)
	}
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func (p *rpStartPhase) outputAAD(generation uint64) (envelope.Context, error) {
	if p == nil || p.service == nil || p.input == nil || generation == 0 {
		return envelope.Context{}, identity.InvalidInputError{Field: "oauth_start_output"}
	}
	plain, err := json.Marshal(struct {
		Input      rpStartInput
		Generation uint64
		Profile    [32]byte
	}{*p.input, generation, p.service.profile})
	if err != nil {
		return envelope.Context{}, identity.InvalidInputError{Field: "oauth_start_output"}
	}
	defer clear(plain)
	digest := sha256.Sum256(plain)
	return envelope.NewContext(map[string]string{"profile": "identity-oauth-rp-start-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func rpStartBindingAAD(tenant string, profile oauth.ProviderProfile, transactionID string, stateDigest [32]byte, purpose string) (envelope.Context, error) {
	if purpose != "binding" && purpose != "state-proof" {
		return envelope.Context{}, identity.InvalidInputError{Field: "oauth_rp_binding"}
	}
	b, err := newRPVerifierBinding(tenant, profile, transactionID, stateDigest, "identity.account.link-start")
	if err != nil {
		return envelope.Context{}, err
	}
	aad, err := b.aad()
	if err != nil {
		return envelope.Context{}, err
	}
	digest := sha256.Sum256(aad.AdditionalData())
	return envelope.NewContext(map[string]string{"profile": "identity-oauth-rp-" + purpose + "-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (s *LinkService) sealRP(ctx context.Context, aad envelope.Context, plain []byte) ([]byte, error) {
	sealed, err := s.envelopes.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: s.config().CurrentEnvelopeKey, Context: aad})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return sealed.MarshalBinary()
}
func (s *LinkService) openRP(ctx context.Context, aad envelope.Context, wire []byte, limit int) ([]byte, error) {
	if len(wire) == 0 || len(wire) > limit {
		return nil, identity.ForbiddenError{}
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	plain, err := s.envelopes.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil || len(plain) > limit {
		clear(plain)
		return nil, identity.ForbiddenError{}
	}
	return plain, nil
}
func decodeRPOutput(plain []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *rpStartPhase) stateLifetime() (time.Time, time.Time, error) {
	original, err := p.originalSession()
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	spec, err := original.Bindings()
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	life, err := original.Lifetime(p.input.Started)
	if err != nil || !life.Fresh {
		return time.Time{}, time.Time{}, identity.ForbiddenError{}
	}
	policy, err := spec.Remember.Bindings()
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	// This closed profile admits password sessions only. Freshness starts at the
	// original completed proof, not at RP initiation or its 20-second admission.
	if spec.Authentication.Kind != session.AuthenticationVerified || spec.Authentication.Proof.Method != "password" {
		return time.Time{}, time.Time{}, identity.ForbiddenError{}
	}
	issued := p.input.Started.UTC().Truncate(time.Second)
	expires := p.input.Started.Add(p.service.config().StateLifetime)
	for _, deadline := range []time.Time{life.ExpiresAt, spec.Authentication.Proof.IssuedAt.Add(policy.FreshFor)} {
		if deadline.Before(expires) {
			expires = deadline
		}
	}
	expires = expires.UTC().Truncate(time.Second)
	if !expires.After(p.input.Started) || !rpVerifierLifetime(issued, expires) {
		return time.Time{}, time.Time{}, identity.ForbiddenError{}
	}
	return issued, expires, nil
}

func (p *rpStartPhase) GenerateFeaturePreparation(ctx context.Context, command identity.Command, generation uint64) ([]byte, error) {
	if err := p.ValidateFeaturePreparation(command, kernel.CommandPlan{}); err != nil {
		return nil, err
	}
	return p.generateOutput(ctx, generation)
}

func (p *rpStartPhase) generateOutput(ctx context.Context, generation uint64) ([]byte, error) {
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	issued, expires, err := p.stateLifetime()
	if err != nil {
		return nil, err
	}
	s, c, b := p.service, p.service.config(), p.input.binding()
	profile, ok := s.profiles[p.input.Provider]
	if !ok {
		return nil, identity.ForbiddenError{}
	}
	var state, nonce, verifier [32]byte
	defer clear(state[:])
	defer clear(nonce[:])
	defer clear(verifier[:])
	for _, v := range [][]byte{state[:], nonce[:], verifier[:]} {
		if _, err = rand.Read(v); err != nil {
			return nil, identity.UnavailableError{}
		}
	}
	callbackID, err := identity.NewCommandID()
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	accountID, err := identity.NewSubjectID()
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	encoded := []byte(base64.RawURLEncoding.EncodeToString(verifier[:]))
	defer clear(encoded)
	challenge := sha256.Sum256(encoded)
	digest := rpStateDigest(c.StateKeys[c.CurrentStateKeyVersion], c.CurrentStateKeyVersion, b.TenantID, profile.ID, state[:])
	vb, err := newRPVerifierBinding(string(b.TenantID), profile, b.RecordID, digest, b.OperationID)
	if err != nil {
		return nil, err
	}
	pkce, err := s.verifiers.seal(ctx, vb, encoded, issued, expires)
	if err != nil {
		return nil, err
	}
	binding := rpStartBinding{Schema: 1, Input: *p.input, Provider: profile, CallbackCommandID: callbackID, AccountRecordID: string(accountID), State: base64.RawURLEncoding.EncodeToString(state[:]), Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]), Challenge: base64.RawURLEncoding.EncodeToString(challenge[:]), StateKeyVersion: c.CurrentStateKeyVersion, StateReplayKeyVersion: c.Capability.CurrentReplayKeyVersion, StateDigest: digest, PKCEKeyVersion: pkce.keyVersion, PKCECommitment: pkce.commitment, IssuedAt: issued, ExpiresAt: expires}
	plain, err := json.Marshal(binding)
	if err != nil {
		return nil, identity.InvalidInputError{Field: "oauth_rp_binding"}
	}
	defer clear(plain)
	bindingDigest := sha256.Sum256(plain)
	baad, err := rpStartBindingAAD(string(b.TenantID), profile, b.RecordID, digest, "binding")
	if err != nil {
		return nil, err
	}
	prepared, err := s.issuer.Prepare(ctx, b, []capability.Payload{{Version: 1, Issuer: c.Capability.Crypto.Issuer, Audiences: []string{c.Capability.Audience}, Subject: string(b.UserID), Resource: b.RecordID, Operation: "identity.oauth.callback", IssuedAt: issued, NotBefore: issued, ExpiresAt: expires, Tenant: string(b.TenantID), CorrelationID: b.CorrelationID, MaxUses: 1, Caveats: map[string]string{"identity.oauth.rp.binding": base64.RawURLEncoding.EncodeToString(bindingDigest[:])}}})
	if err != nil {
		return nil, err
	}
	plan, err := prepared.Plan()
	if err != nil {
		return nil, err
	}
	if len(plan.Grants) != 1 {
		return nil, identity.ForbiddenError{}
	}
	stored, err := json.Marshal(rpStoredTransaction{Binding: binding, State: rpStoredGrant(plan.Grants[0])})
	if err != nil || len(stored) > 49152 {
		return nil, identity.InvalidInputError{Field: "oauth_rp_binding"}
	}
	defer clear(stored)
	bindingCiphertext, err := s.sealRP(ctx, baad, stored)
	if err != nil {
		return nil, err
	}
	paad, err := rpStartBindingAAD(string(b.TenantID), profile, b.RecordID, digest, "state-proof")
	if err != nil {
		return nil, err
	}
	var stateProof []byte
	checkpoint, err := s.checkpoint.CheckpointPreparation(ctx, prepared, generation, func(ctx context.Context, index uint16, proof []byte) error {
		if index != 0 || len(stateProof) != 0 {
			return identity.ForbiddenError{}
		}
		var e error
		stateProof, e = s.sealRP(ctx, paad, proof)
		return e
	})
	if err != nil {
		return nil, err
	}
	storedPlan := rpStoredIssuancePlan{Contributor: plan.Contributor, Grants: make([]rpStoredGrant, len(plan.Grants))}
	for i, g := range plan.Grants {
		storedPlan.Grants[i] = rpStoredGrant(g)
	}
	out := rpStartOutput{Schema: 1, Generation: generation, Binding: binding, BindingCiphertext: bindingCiphertext, PKCECiphertext: pkce.ciphertext, StateProofCiphertext: stateProof, Checkpoint: checkpoint, Plan: storedPlan}
	output, err := json.Marshal(out)
	if err != nil || len(output) > 768<<10 {
		return nil, identity.InvalidInputError{Field: "oauth_start_output"}
	}
	defer clear(output)
	return s.sealRP(ctx, aad, output)
}

func (s *LinkService) openRPStartBinding(ctx context.Context, tenant identity.TenantID, wire []byte, profile oauth.ProviderProfile, transactionID string, digest [32]byte) (rpStartBinding, error) {
	retained, _, err := s.openRPStoredTransaction(ctx, tenant, wire, profile, transactionID, digest)
	return retained, err
}

func (s *LinkService) openRPStoredTransaction(ctx context.Context, tenant identity.TenantID, wire []byte, profile oauth.ProviderProfile, transactionID string, digest [32]byte) (rpStartBinding, kernel.CapabilityPlan, error) {
	var out rpStoredTransaction
	aad, err := rpStartBindingAAD(string(tenant), profile, transactionID, digest, "binding")
	if err != nil {
		return rpStartBinding{}, kernel.CapabilityPlan{}, err
	}
	plain, err := s.openRP(ctx, aad, wire, 65536)
	if err != nil {
		return rpStartBinding{}, kernel.CapabilityPlan{}, err
	}
	defer clear(plain)
	if decodeRPOutput(plain, &out) != nil {
		return rpStartBinding{}, kernel.CapabilityPlan{}, identity.ForbiddenError{}
	}
	b, state := out.Binding, kernel.CapabilityPlan(out.State)
	if b.Input.binding().TenantID != tenant || b.Input.binding().RecordID != transactionID || b.StateDigest != digest || !reflect.DeepEqual(b.Provider, profile) || b.Input.Profile != s.profile || (&rpStartPhase{service: s, input: &b.Input}).validateOutputBinding(b) != nil || state.CapabilityID == "" || state.Purpose != "identity.oauth.callback" || state.MaxUses != 1 || state.ReplayKeyVersion != b.StateReplayKeyVersion || state.ProofFingerprint == ([32]byte{}) || state.ReplayDigest == ([32]byte{}) || !state.ExpiresAt.Equal(b.ExpiresAt) {
		return rpStartBinding{}, kernel.CapabilityPlan{}, identity.ForbiddenError{}
	}
	return b, state, nil
}

func (p *rpStartPhase) validateOutputBinding(out rpStartBinding) error {
	b := p.input.binding()
	profile, ok := p.service.profiles[p.input.Provider]
	issued, expires, err := p.stateLifetime()
	if err != nil || !ok || out.Schema != 1 || !reflect.DeepEqual(out.Input, *p.input) || !reflect.DeepEqual(out.Provider, profile) || !out.IssuedAt.Equal(issued) || !out.ExpiresAt.Equal(expires) || out.PKCECommitment == ([32]byte{}) || p.service.verifiers.commitmentKeys[out.PKCEKeyVersion] == nil || p.service.config().StateKeys[out.StateKeyVersion] == ([32]byte{}) || out.StateReplayKeyVersion == 0 || p.service.config().Capability.RetainedReplayKeys[out.StateReplayKeyVersion] == ([32]byte{}) {
		return identity.ForbiddenError{}
	}
	if _, err := identity.ParseCommandID(string(out.CallbackCommandID)); err != nil {
		return identity.ForbiddenError{}
	}
	if _, err := identity.ParseIdentifierID(out.AccountRecordID); err != nil {
		return identity.ForbiddenError{}
	}
	for _, value := range []string{out.State, out.Nonce, out.Challenge} {
		raw, e := base64.RawURLEncoding.Strict().DecodeString(value)
		valid := e == nil && len(raw) == 32 && len(value) == 43
		clear(raw)
		if !valid {
			return identity.ForbiddenError{}
		}
	}
	raw, _ := base64.RawURLEncoding.Strict().DecodeString(out.State)
	defer clear(raw)
	want := rpStateDigest(p.service.config().StateKeys[out.StateKeyVersion], out.StateKeyVersion, b.TenantID, profile.ID, raw)
	if !hmac.Equal(want[:], out.StateDigest[:]) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *rpStartPhase) restoreOutput(ctx context.Context, generation uint64, wire []byte) (rpStartOutput, capabilitypg.PreparedIssuance, kernel.CapabilityIssuancePlan, error) {
	var out rpStartOutput
	fail := func(err error) (rpStartOutput, capabilitypg.PreparedIssuance, kernel.CapabilityIssuancePlan, error) {
		return rpStartOutput{}, capabilitypg.PreparedIssuance{}, kernel.CapabilityIssuancePlan{}, err
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return fail(err)
	}
	plain, err := p.service.openRP(ctx, aad, wire, 1<<20)
	if err != nil {
		return fail(err)
	}
	defer clear(plain)
	if decodeRPOutput(plain, &out) != nil || out.Schema != 1 || out.Generation != generation || p.validateOutputBinding(out.Binding) != nil || len(out.PKCECiphertext) == 0 || len(out.PKCECiphertext) > 4096 || len(out.StateProofCiphertext) == 0 || len(out.StateProofCiphertext) > 65536 || len(out.BindingCiphertext) == 0 || len(out.BindingCiphertext) > 65536 || len(out.Checkpoint) == 0 || len(out.Checkpoint) > 512<<10 || len(out.Plan.Grants) != 1 || out.Plan.Grants[0].Purpose != "identity.oauth.callback" || !out.Plan.Grants[0].ExpiresAt.Equal(out.Binding.ExpiresAt) || out.Plan.Grants[0].MaxUses != 1 {
		return fail(identity.ForbiddenError{})
	}
	b := p.input.binding()
	persisted, state, err := p.service.openRPStoredTransaction(ctx, b.TenantID, out.BindingCiphertext, out.Binding.Provider, b.RecordID, out.Binding.StateDigest)
	if err != nil || !reflect.DeepEqual(persisted, out.Binding) || state != kernel.CapabilityPlan(out.Plan.Grants[0]) {
		return fail(identity.ForbiddenError{})
	}
	plan := out.Plan.native()
	prepared, err := p.service.checkpoint.RestorePreparation(ctx, b, generation, plan, out.Checkpoint)
	if err != nil {
		return fail(err)
	}
	return out, prepared, plan, nil
}

func (p *rpStartPhase) RestoreFeaturePreparation(ctx context.Context, command identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if err := p.ValidateFeaturePreparation(command, kernel.CommandPlan{}); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	_, _, issuance, err := p.restoreOutput(ctx, generation, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	_, registry, err := p.service.startCoordinator(p)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	_, counter, err := p.command()
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plan, err := p.declaration(ctx, command, counter, registry)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plan.Contributors = append(plan.Contributors, p.service.issuer.Descriptor())
	plan.CapabilityIssuance = &issuance
	return command, plan, nil
}

func (p *rpStartPhase) persist(ctx context.Context, w kernel.Work, out rpStartOutput) error {
	if err := p.validateOutputBinding(out.Binding); err != nil {
		return err
	}
	b := p.input.binding()
	v := out.Binding
	original, err := p.originalSession()
	if err != nil {
		return err
	}
	record, err := original.Bindings()
	if err != nil {
		return err
	}
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return identity.InvalidInputError{Field: "oauth_start_command"}
	}
	n, err := w.Exec(ctx, `INSERT INTO `+rpQuotedSchema(p.service.config().Schema)+`.transactions(tenant_id,transaction_id,origin_command_id,operation,user_id,session_id,session_version,provider_id,configuration_version,issuer,client_id,redirect_uri,response_mode,state_key_version,state_digest,pkce_key_version,pkce_commitment,pkce_ciphertext,state_proof_ciphertext,binding_ciphertext,issued_at,expires_at,version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,1)`, string(b.TenantID), b.RecordID, command, b.OperationID, string(b.UserID), record.SessionID, record.Version, v.Provider.ID, v.Provider.Version, v.Provider.Issuer, v.Provider.ClientID, v.Provider.RedirectURI, v.Provider.ResponseMode, v.StateKeyVersion, v.StateDigest[:], v.PKCEKeyVersion, v.PKCECommitment[:], out.PKCECiphertext, out.StateProofCiphertext, out.BindingCiphertext, v.IssuedAt, v.ExpiresAt)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.UnavailableError{}
	}
	return nil
}

func (p *rpStartPhase) committedRedirect(ctx context.Context) (oauth.LinkStartResult, error) {
	var result oauth.LinkStartResult
	if p == nil || p.input == nil {
		return result, identity.ForbiddenError{}
	}
	b := p.input.binding()
	profile, ok := p.service.profiles[p.input.Provider]
	if !ok {
		return result, identity.ForbiddenError{}
	}
	var wire, digest, commitment []byte
	var stateVersion, pkceVersion, version uint64
	var issued, expires, now time.Time
	var erased *time.Time
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return result, identity.ForbiddenError{}
	}
	err = p.service.pool.Raw().QueryRow(ctx, `SELECT binding_ciphertext,state_digest,state_key_version,pkce_commitment,pkce_key_version,issued_at,expires_at,version,secrets_erased_at,clock_timestamp() FROM `+rpQuotedSchema(p.service.config().Schema)+`.transactions WHERE tenant_id=$1 AND transaction_id=$2 AND origin_command_id=$3 AND operation=$4 AND user_id=$5 AND provider_id=$6 AND configuration_version=$7 AND issuer=$8 AND client_id=$9 AND redirect_uri=$10 AND response_mode=$11`, string(b.TenantID), b.RecordID, command, b.OperationID, string(b.UserID), profile.ID, profile.Version, profile.Issuer, profile.ClientID, profile.RedirectURI, profile.ResponseMode).Scan(&wire, &digest, &stateVersion, &commitment, &pkceVersion, &issued, &expires, &version, &erased, &now)
	if err != nil || len(digest) != 32 || len(commitment) != 32 || version != 1 || erased != nil || stateVersion == 0 || stateVersion > 1<<32-1 || pkceVersion == 0 || pkceVersion > 1<<32-1 {
		return result, identity.ForbiddenError{}
	}
	var stateDigest [32]byte
	copy(stateDigest[:], digest)
	retained, err := p.service.openRPStartBinding(ctx, b.TenantID, wire, profile, b.RecordID, stateDigest)
	if err != nil || p.validateOutputBinding(retained) != nil || retained.StateKeyVersion != uint32(stateVersion) || retained.PKCEKeyVersion != uint32(pkceVersion) || !bytes.Equal(retained.PKCECommitment[:], commitment) || !retained.IssuedAt.Equal(issued) || !retained.ExpiresAt.Equal(expires) || now.Before(issued) || !now.Before(expires) {
		return result, identity.ForbiddenError{}
	}
	original, err := p.originalSession()
	if err != nil || !p.service.possesses(b.TenantID, p.request.Session, p.request.CSRFToken, original) {
		return result, identity.ForbiddenError{}
	}
	token, err := session.ParseToken(p.request.Session.Token())
	if err != nil {
		return result, identity.ForbiddenError{}
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return result, identity.ForbiddenError{}
	}
	current, err := p.service.sessions.Get(ctx, session.GetRequest{TenantID: b.TenantID, Credential: credential})
	if err != nil || !current.Authenticated || current.ValidateAt(p.service.config().Session.Validation.Clock.Now()) != nil || !p.service.possesses(b.TenantID, p.request.Session, p.request.CSRFToken, current.Session) {
		return result, identity.ForbiddenError{}
	}
	fields, err := sessionpg.OriginalSessionFields(current.Session)
	if err != nil || !sameRPFields(fields, p.input.Session) {
		return result, identity.ForbiddenError{}
	}
	life, err := current.Session.Lifetime(now.UTC())
	if err != nil || !life.Fresh {
		return result, identity.ForbiddenError{}
	}
	factors, err := mfapg.ReadOAuthLinkFactors(ctx, p.service.pool, b.TenantID, b.UserID, p.service.config().Session.Repository.MaximumDuration)
	if err != nil || factors.Version() != p.input.FactorVersion {
		return result, identity.ForbiddenError{}
	}
	decision, err := p.service.config().Coordinator.AdmissionPolicy.Authorization.Decide(ctx, p.request.Caller)
	if err != nil || decision.Outcome != authorization.Allow || uint64(decision.Revision) != b.PolicyVersion {
		return result, identity.ForbiddenError{}
	}
	provider, ok := p.service.providers.Lookup(profile.ID)
	if !ok || !reflect.DeepEqual(provider.Profile(), profile) {
		return result, identity.ForbiddenError{}
	}
	authorization, err := provider.Authorization(ctx, oauth.AuthorizationParameters{State: retained.State, Nonce: retained.Nonce, PKCEChallenge: retained.Challenge})
	if err != nil {
		return result, err
	}
	redirect, err := url.Parse(authorization.URL())
	if err != nil {
		return result, identity.UnavailableError{}
	}
	return oauth.LinkStartResult{RedirectURI: *redirect, TransactionID: b.RecordID, ExpiresAt: retained.ExpiresAt}, nil
}
