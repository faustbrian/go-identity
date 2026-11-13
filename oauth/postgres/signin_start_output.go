package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"time"

	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type signinStoredAdmission risk.PreparedAuthenticationAdmission

// This projection retains only non-exchange metadata after secret erasure.
// The canonical capability proof and PKCE verifier have separate ciphertexts.
type signinRPBinding struct {
	Schema                  uint8
	Input                   signinStartInput
	Provider                oauth.ProviderProfile
	CallbackCommandID       identity.CommandID
	State, Nonce, Challenge string
	StateKeyVersion         uint32
	StateReplayKeyVersion   uint32
	StateDigest             [32]byte
	PKCEKeyVersion          uint32
	PKCECommitment          [32]byte
	IssuedAt, ExpiresAt     time.Time
}

type signinStoredTransaction struct {
	Binding      signinRPBinding
	State        rpStoredGrant
	ResultFields []identity.FeatureField `json:",omitempty"`
	Denied       bool                    `json:",omitempty"`
}

type signinStartOutput struct {
	Schema                                                              uint8
	Generation                                                          uint64
	Binding                                                             signinRPBinding
	Admission                                                           signinStoredAdmission
	BindingCiphertext, PKCECiphertext, StateProofCiphertext, Checkpoint []byte
	Plan                                                                rpStoredIssuancePlan
}

func (p *signinStartPhase) outputAAD(generation uint64) (envelope.Context, error) {
	if p == nil || p.service == nil || p.input == nil || generation == 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	wire, err := json.Marshal(struct {
		Input      signinStartInput
		Generation uint64
	}{*p.input, generation})
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	defer clear(wire)
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{"profile": "identity-oauth-signin-start-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func signinBindingAAD(b signinRPBinding, purpose string) (envelope.Context, error) {
	if purpose != "binding" && purpose != "state-proof" {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	command := identity.CommandBinding(b.Input.Binding)
	binding, err := newRPVerifierBinding(string(command.TenantID), b.Provider, command.RecordID, b.StateDigest, command.OperationID)
	if err != nil {
		return envelope.Context{}, err
	}
	aad, err := binding.aad()
	if err != nil {
		return envelope.Context{}, err
	}
	digest := sha256.Sum256(aad.AdditionalData())
	return envelope.NewContext(map[string]string{"profile": "identity-oauth-signin-rp-" + purpose + "-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *signinStartPhase) stateLifetime() (time.Time, time.Time, error) {
	if p == nil || p.input == nil {
		return time.Time{}, time.Time{}, identity.ForbiddenError{}
	}
	flow, err := p.flow.Bindings()
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	issued := p.input.Started.UTC().Truncate(time.Second)
	expires := p.input.Started.Add(p.service.config.StateLifetime)
	if flow.Binding.ExpiresAt.Before(expires) {
		expires = flow.Binding.ExpiresAt
	}
	expires = expires.UTC().Truncate(time.Second)
	if !expires.After(p.input.Started) || !rpVerifierLifetime(issued, expires) {
		return time.Time{}, time.Time{}, identity.ForbiddenError{}
	}
	return issued, expires, nil
}

func (p *signinStartPhase) generateOutput(ctx context.Context, generation uint64, admission risk.AuthenticationAdmission) ([]byte, error) {
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	issued, expires, err := p.stateLifetime()
	if err != nil {
		return nil, err
	}
	s, c := p.service, p.service.config
	b := identity.CommandBinding(p.input.Binding)
	profile, ok := s.profiles[p.input.Provider]
	if !ok {
		return nil, identity.ForbiddenError{}
	}
	var state, nonce, verifier [32]byte
	defer clear(state[:])
	defer clear(nonce[:])
	defer clear(verifier[:])
	for _, raw := range [][]byte{state[:], nonce[:], verifier[:]} {
		if _, err := rand.Read(raw); err != nil {
			return nil, identity.UnavailableError{}
		}
	}
	callbackID, err := identity.NewCommandID()
	if err != nil {
		return nil, err
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
	binding := signinRPBinding{Schema: 1, Input: *p.input, Provider: profile, CallbackCommandID: callbackID, State: base64.RawURLEncoding.EncodeToString(state[:]), Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]), Challenge: base64.RawURLEncoding.EncodeToString(challenge[:]), StateKeyVersion: c.CurrentStateKeyVersion, StateReplayKeyVersion: c.Capability.CurrentReplayKeyVersion, StateDigest: digest, PKCEKeyVersion: pkce.keyVersion, PKCECommitment: pkce.commitment, IssuedAt: issued, ExpiresAt: expires}
	plainBinding, err := json.Marshal(binding)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	defer clear(plainBinding)
	bindingDigest := sha256.Sum256(plainBinding)
	prepared, err := s.issuer.Prepare(ctx, b, []capability.Payload{{Version: 1, Issuer: c.Capability.Crypto.Issuer, Audiences: []string{c.Capability.Audience}, Subject: b.AnonymousFlowID, Resource: b.RecordID, Operation: "identity.oauth.callback", IssuedAt: issued, NotBefore: issued, ExpiresAt: expires, Tenant: string(b.TenantID), CorrelationID: b.CorrelationID, MaxUses: 1, Caveats: map[string]string{"identity.oauth.rp.binding": base64.RawURLEncoding.EncodeToString(bindingDigest[:])}}})
	if err != nil {
		return nil, err
	}
	plan, err := prepared.Plan()
	if err != nil || len(plan.Grants) != 1 {
		return nil, identity.ForbiddenError{}
	}
	stored, err := json.Marshal(signinStoredTransaction{Binding: binding, State: rpStoredGrant(plan.Grants[0])})
	if err != nil || len(stored) > 49152 {
		return nil, identity.UnavailableError{}
	}
	defer clear(stored)
	baad, err := signinBindingAAD(binding, "binding")
	if err != nil {
		return nil, err
	}
	sealedBinding, err := s.seal(ctx, baad, stored)
	if err != nil {
		return nil, err
	}
	paad, err := signinBindingAAD(binding, "state-proof")
	if err != nil {
		return nil, err
	}
	var sealedProof []byte
	checkpoint, err := s.checkpoint.CheckpointPreparation(ctx, prepared, generation, func(ctx context.Context, index uint16, proof []byte) error {
		if index != 0 || len(sealedProof) != 0 {
			return identity.ForbiddenError{}
		}
		var err error
		sealedProof, err = s.seal(ctx, paad, proof)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := signinStartOutput{Schema: 1, Generation: generation, Binding: binding, Admission: signinStoredAdmission(admission.Prepared()), BindingCiphertext: sealedBinding, PKCECiphertext: pkce.ciphertext, StateProofCiphertext: sealedProof, Checkpoint: checkpoint, Plan: rpStoredIssuancePlan{Contributor: plan.Contributor, Grants: []rpStoredGrant{rpStoredGrant(plan.Grants[0])}}}
	plain, err := json.Marshal(out)
	if err != nil || len(plain) > 768<<10 {
		return nil, identity.InvalidInputError{Field: "oauth_signin_output"}
	}
	defer clear(plain)
	return s.seal(ctx, aad, plain)
}

func (p *signinStartPhase) validateBinding(b signinRPBinding) error {
	issued, expires, err := p.stateLifetime()
	profile, ok := p.service.profiles[p.input.Provider]
	if err != nil || !ok || b.Schema != 1 || !reflect.DeepEqual(b.Input, *p.input) || !reflect.DeepEqual(b.Provider, profile) || !issued.Equal(b.IssuedAt) || !expires.Equal(b.ExpiresAt) || b.StateDigest == ([32]byte{}) || b.PKCECommitment == ([32]byte{}) || p.service.verifiers.commitmentKeys[b.PKCEKeyVersion] == nil || p.service.config.Capability.RetainedReplayKeys[b.StateReplayKeyVersion] == ([32]byte{}) {
		return identity.ForbiddenError{}
	}
	if _, err := identity.ParseCommandID(string(b.CallbackCommandID)); err != nil {
		return identity.ForbiddenError{}
	}
	for _, value := range []string{b.State, b.Nonce, b.Challenge} {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
		valid := err == nil && len(value) == 43 && len(raw) == 32
		clear(raw)
		if !valid {
			return identity.ForbiddenError{}
		}
	}
	key := p.service.config.StateKeys[b.StateKeyVersion]
	if key == ([32]byte{}) {
		return identity.ForbiddenError{}
	}
	raw, _ := base64.RawURLEncoding.Strict().DecodeString(b.State)
	defer clear(raw)
	command := identity.CommandBinding(p.input.Binding)
	digest := rpStateDigest(key, b.StateKeyVersion, command.TenantID, profile.ID, raw)
	if !hmac.Equal(digest[:], b.StateDigest[:]) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *signinStartPhase) openTransaction(ctx context.Context, binding signinRPBinding, wire []byte) (signinStoredTransaction, error) {
	stored, err := p.service.openSigninTransaction(ctx, binding, wire)
	if err != nil {
		return signinStoredTransaction{}, err
	}
	if p.validateBinding(stored.Binding) != nil {
		return signinStoredTransaction{}, identity.ForbiddenError{}
	}
	return stored, nil
}

// Authentication of browser intent/current ownership follows decryption at
// both entry points; row-scoped AAD alone is not callback admission.
func (s *SigninService) openSigninTransaction(ctx context.Context, binding signinRPBinding, wire []byte) (signinStoredTransaction, error) {
	aad, err := signinBindingAAD(binding, "binding")
	if err != nil {
		return signinStoredTransaction{}, err
	}
	plain, err := s.open(ctx, aad, wire, 65536)
	if err != nil {
		return signinStoredTransaction{}, err
	}
	defer clear(plain)
	var stored signinStoredTransaction
	if decodeRPOutput(plain, &stored) != nil || stored.Binding.StateDigest != binding.StateDigest {
		return signinStoredTransaction{}, identity.ForbiddenError{}
	}
	state := kernel.CapabilityPlan(stored.State)
	if state.CapabilityID == "" || state.Purpose != "identity.oauth.callback" || state.MaxUses != 1 || state.ProofFingerprint == ([32]byte{}) || state.ReplayDigest == ([32]byte{}) || state.ReplayKeyVersion != stored.Binding.StateReplayKeyVersion || !state.ExpiresAt.Equal(stored.Binding.ExpiresAt) {
		return signinStoredTransaction{}, identity.ForbiddenError{}
	}
	return stored, nil
}

func (p *signinStartPhase) restoreOutput(ctx context.Context, generation uint64, wire []byte) (signinStartOutput, capabilitypg.PreparedIssuance, kernel.CapabilityIssuancePlan, error) {
	fail := func(err error) (signinStartOutput, capabilitypg.PreparedIssuance, kernel.CapabilityIssuancePlan, error) {
		return signinStartOutput{}, capabilitypg.PreparedIssuance{}, kernel.CapabilityIssuancePlan{}, err
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return fail(err)
	}
	plain, err := p.service.open(ctx, aad, wire, 1<<20)
	if err != nil {
		return fail(err)
	}
	defer clear(plain)
	var out signinStartOutput
	if decodeRPOutput(plain, &out) != nil || out.Schema != 1 || out.Generation != generation || p.validateBinding(out.Binding) != nil || len(out.PKCECiphertext) < 1 || len(out.PKCECiphertext) > 4096 || len(out.StateProofCiphertext) < 1 || len(out.StateProofCiphertext) > 65536 || len(out.Plan.Grants) != 1 || len(out.Checkpoint) < 1 || len(out.Checkpoint) > 512<<10 {
		return fail(identity.ForbiddenError{})
	}
	stored, err := p.openTransaction(ctx, out.Binding, out.BindingCiphertext)
	if err != nil || !reflect.DeepEqual(stored.Binding, out.Binding) || stored.State != out.Plan.Grants[0] {
		return fail(identity.ForbiddenError{})
	}
	plan := out.Plan.native()
	prepared, err := p.service.checkpoint.RestorePreparation(ctx, identity.CommandBinding(p.input.Binding), generation, plan, out.Checkpoint)
	if err != nil {
		return fail(err)
	}
	return out, prepared, plan, nil
}

func (p *signinStartPhase) persist(ctx context.Context, w kernel.Work, output signinStartOutput) error {
	b, v := identity.CommandBinding(p.input.Binding), output.Binding
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return identity.ForbiddenError{}
	}
	n, err := w.Exec(ctx, `INSERT INTO `+rpQuotedSchema(p.service.config.Schema)+`.transactions(tenant_id,transaction_id,origin_command_id,operation,preauth_id,provider_id,configuration_version,issuer,client_id,redirect_uri,response_mode,state_key_version,state_digest,pkce_key_version,pkce_commitment,pkce_ciphertext,state_proof_ciphertext,binding_ciphertext,issued_at,expires_at,version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,1)`, string(b.TenantID), b.RecordID, id, b.OperationID, b.AnonymousFlowID, v.Provider.ID, v.Provider.Version, v.Provider.Issuer, v.Provider.ClientID, v.Provider.RedirectURI, v.Provider.ResponseMode, v.StateKeyVersion, v.StateDigest[:], v.PKCEKeyVersion, v.PKCECommitment[:], output.PKCECiphertext, output.StateProofCiphertext, output.BindingCiphertext, v.IssuedAt, v.ExpiresAt)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.UnavailableError{}
	}
	return nil
}

func (p *signinStartPhase) committedRedirect(ctx context.Context) (oauth.SigninStartResult, error) {
	b := identity.CommandBinding(p.input.Binding)
	profile := p.service.profiles[p.input.Provider]
	id, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	var wire, digest, commitment []byte
	var stateVersion, pkceVersion uint32
	var issued, expires, now time.Time
	err := p.service.pool.Raw().QueryRow(ctx, `SELECT binding_ciphertext,state_digest,state_key_version,pkce_commitment,pkce_key_version,issued_at,expires_at,clock_timestamp() FROM `+rpQuotedSchema(p.service.config.Schema)+`.transactions WHERE tenant_id=$1 AND transaction_id=$2 AND origin_command_id=$3 AND operation=$4 AND preauth_id=$5 AND user_id IS NULL AND session_id IS NULL AND provider_id=$6 AND configuration_version=$7 AND issuer=$8 AND client_id=$9 AND redirect_uri=$10 AND response_mode='query' AND version=1 AND secrets_erased_at IS NULL`, string(b.TenantID), b.RecordID, id, b.OperationID, b.AnonymousFlowID, profile.ID, profile.Version, profile.Issuer, profile.ClientID, profile.RedirectURI).Scan(&wire, &digest, &stateVersion, &commitment, &pkceVersion, &issued, &expires, &now)
	if err != nil || len(digest) != 32 || len(commitment) != 32 || now.Before(issued) || !now.Before(expires) {
		return oauth.SigninStartResult{}, identity.ForbiddenError{}
	}
	probe := signinRPBinding{Input: *p.input, Provider: profile, StateDigest: [32]byte(digest)}
	stored, err := p.openTransaction(ctx, probe, wire)
	v := stored.Binding
	if err != nil || v.StateKeyVersion != stateVersion || v.PKCEKeyVersion != pkceVersion || !bytes.Equal(v.PKCECommitment[:], commitment) || !v.IssuedAt.Equal(issued) || !v.ExpiresAt.Equal(expires) || checkSigninBrowser(p.request, p.flow, p.service.config.FlowKeys, b.PolicyID, b.PolicyVersion, now.UTC()) != nil {
		return oauth.SigninStartResult{}, identity.ForbiddenError{}
	}
	if err := sessionpg.RequirePreAuth(ctx, p.service.pool.Raw(), p.service.config.Session, p.flow); err != nil {
		return oauth.SigninStartResult{}, err
	}
	provider, ok := p.service.providers.Lookup(profile.ID)
	if !ok {
		return oauth.SigninStartResult{}, identity.ForbiddenError{}
	}
	request, err := provider.Authorization(ctx, oauth.AuthorizationParameters{State: v.State, Nonce: v.Nonce, PKCEChallenge: v.Challenge})
	if err != nil {
		return oauth.SigninStartResult{}, err
	}
	redirect, err := url.Parse(request.URL())
	if err != nil || redirect == nil {
		return oauth.SigninStartResult{}, identity.UnavailableError{}
	}
	// A terminal coordinator receipt proves the original write, not current
	// authority to resume the browser redirect. Replays must retain its frozen
	// epochs and fail closed after suspension or any intervening epoch change.
	readStarted := time.Now()
	directory, err := p.service.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.service.config.GlobalAuthorityID, TenantID: b.TenantID})
	if err != nil {
		return oauth.SigninStartResult{}, err
	}
	if !directory.Enabled || directory.GlobalVersion != p.input.GlobalVersion || directory.TenantVersion != p.input.TenantVersion || time.Since(readStarted) >= 20*time.Second {
		return oauth.SigninStartResult{}, identity.ForbiddenError{}
	}
	return oauth.SigninStartResult{RedirectURI: *redirect, TransactionID: b.RecordID, ExpiresAt: expires}, nil
}
