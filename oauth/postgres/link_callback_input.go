package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// Authenticated lookup data is not primary admission or exchange permission.
// The coordinator alone reserves state and acknowledges preparation before the
// callback owner may release PKCE. No verifier plaintext is represented here.
type rpCallbackFlow struct {
	binding    rpStartBinding
	original   session.Session
	stateProof capability.Proof
	stateGrant capability.Grant
	statePlan  kernel.CapabilityPlan
	pkce       rpSealedVerifier
	loadedAt   time.Time
	erased     bool
}

func (f *rpCallbackFlow) destroy() {
	if f == nil {
		return
	}
	_ = f.stateProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	f.stateProof = capability.Proof{}
	clear(f.pkce.ciphertext)
	f.pkce.ciphertext = nil
}

// Own RP data only: no account-link rows, capability SQL, leases or exchange
// status are read or written here. The original command journal remains the
// authority for whether generation may run, must resume, or is terminal.
func (s *LinkService) loadRPLinkCallback(ctx context.Context, r oauth.CallbackRequest) (out rpCallbackFlow, err error) {
	if ctx == nil || s == nil || s.pool == nil || s.pool.Raw() == nil || s.config == nil || r.Validate() != nil {
		return out, identity.InvalidInputError{Field: "oauth_callback_input"}
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if err != nil {
			out.destroy()
			out = rpCallbackFlow{}
		}
	}()
	c := s.config()
	profile := r.Callback.Profile()
	current, ok := s.profiles[profile.ID]
	if !ok || !reflect.DeepEqual(profile, current) || r.Origin != c.Origin {
		return out, identity.ForbiddenError{}
	}
	var decoded []byte
	if err := useRPCallbackState(ctx, r.Callback, func(_ context.Context, state []byte) error {
		var err error
		decoded, err = base64.RawURLEncoding.Strict().DecodeString(string(state))
		if err != nil || len(decoded) != 32 {
			return identity.ForbiddenError{}
		}
		return nil
	}); err != nil {
		clear(decoded)
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		return out, identity.ForbiddenError{}
	}
	defer clear(decoded)
	versions := make([]int64, 0, len(c.StateKeys))
	for version := range c.StateKeys {
		versions = append(versions, int64(version))
	}
	slices.Sort(versions)
	digests := make([][]byte, len(versions))
	for index, version := range versions {
		digest := rpStateDigest(c.StateKeys[uint32(version)], uint32(version), r.TenantID, profile.ID, decoded)
		digests[index] = digest[:]
	}
	var started time.Time
	if err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&started); err != nil {
		return out, identity.UnavailableError{}
	}
	// Match retained key/digest PAIRS, never their independent Cartesian sets.
	// A second row is ambiguity, not permission to choose a convenient match.
	rows, err := s.pool.Raw().Query(ctx, `SELECT t.transaction_id,t.origin_command_id,t.user_id,t.session_id,t.session_version::text,
 t.pkce_key_version,t.pkce_commitment,t.pkce_ciphertext,t.state_proof_ciphertext,t.binding_ciphertext,
 t.state_key_version,t.state_digest,t.issued_at,t.expires_at,t.version::text,t.secrets_erased_at
 FROM `+rpQuotedSchema(c.Schema)+`.transactions t JOIN unnest($3::bigint[],$4::bytea[]) AS selected(key_version,digest)
 ON t.state_key_version=selected.key_version AND t.state_digest=selected.digest
 WHERE t.tenant_id=$1 AND t.provider_id=$2 AND t.configuration_version=$5::numeric AND t.issuer=$6 AND t.client_id=$7
 AND t.redirect_uri=$8 AND t.response_mode='query' AND t.operation='identity.account.link-start'
 AND t.user_id IS NOT NULL AND t.preauth_id IS NULL LIMIT 2`, string(r.TenantID), profile.ID, versions, digests, profile.Version, profile.Issuer, profile.ClientID, profile.RedirectURI)
	if err != nil {
		return out, identity.UnavailableError{}
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return out, identity.UnavailableError{}
		}
		return out, identity.ForbiddenError{}
	}
	var transaction, userID, sessionID, sessionVersion, version string
	var origin, commitment, pkce, proof, wire, digest []byte
	var stateVersion, pkceVersion uint32
	var issued, expires time.Time
	var erased *time.Time
	if rows.Scan(&transaction, &origin, &userID, &sessionID, &sessionVersion, &pkceVersion, &commitment, &pkce, &proof, &wire, &stateVersion, &digest, &issued, &expires, &version, &erased) != nil || rows.Next() || rows.Err() != nil {
		return out, identity.UnavailableError{}
	}
	rows.Close()
	var now time.Time
	if err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return out, identity.UnavailableError{}
	}
	started, now = started.UTC(), now.UTC()
	if len(digest) != 32 || len(commitment) != 32 || len(origin) != 16 || now.Before(started) || !now.Before(started.Add(20*time.Second)) || now.Before(issued) || !now.Before(expires) || (erased == nil && version != "1") || (erased != nil && (version != "2" || pkce != nil || proof != nil)) {
		return out, identity.ForbiddenError{}
	}
	var stateDigest [32]byte
	copy(stateDigest[:], digest)
	binding, plan, err := s.openRPStoredTransaction(ctx, r.TenantID, wire, profile, transaction, stateDigest)
	if err != nil {
		return out, err
	}
	original, err := (&rpStartPhase{service: s, input: &binding.Input}).originalSession()
	if err != nil {
		return out, err
	}
	spec, err := original.Bindings()
	originID, originErr := base64.RawURLEncoding.Strict().DecodeString(string(binding.Input.binding().CommandID))
	if err != nil || originErr != nil || !bytes.Equal(originID, origin) || spec.SessionID != sessionID || strconv.FormatUint(spec.Version, 10) != sessionVersion || stateVersion != binding.StateKeyVersion || pkceVersion != binding.PKCEKeyVersion || !bytes.Equal(commitment, binding.PKCECommitment[:]) || !issued.Equal(binding.IssuedAt) || !expires.Equal(binding.ExpiresAt) || !s.ownsSessionBearer(r.TenantID, r.Session, original) || string(binding.Input.binding().UserID) != userID || c.Coordinator.AdmissionPolicy == nil || binding.Input.binding().PolicyVersion != c.Coordinator.AdmissionPolicy.PolicyVersion {
		return out, identity.ForbiddenError{}
	}
	if erased != nil {
		// No new execution may use this metadata-only result: protected admission
		// must deny erased input. Only the existing journal's exact terminal
		// replay may return its original outcome without generation or exchange.
		return rpCallbackFlow{binding: binding, original: original, statePlan: plan, loadedAt: started, erased: true}, nil
	}
	out, err = s.authenticateRPCallback(ctx, r, binding, proof, now)
	if err != nil {
		return out, err
	}
	if out.statePlan != plan {
		return out, identity.ForbiddenError{}
	}
	out.pkce = rpSealedVerifier{ciphertext: bytes.Clone(pkce), commitment: binding.PKCECommitment, keyVersion: binding.PKCEKeyVersion}
	out.loadedAt = started
	return out, nil
}

func (s *LinkService) ownsSessionBearer(tenant identity.TenantID, bearer auth.BearerCredential, original session.Session) bool {
	if s == nil || s.config == nil {
		return false
	}
	spec, err := original.Bindings()
	if err != nil || spec.TenantID != tenant {
		return false
	}
	token, err := session.ParseToken(bearer.Token())
	if err != nil {
		return false
	}
	matched := false
	for _, key := range s.config().Session.Validation.LookupKeys {
		digest, err := token.Digest(key, string(tenant))
		if err == nil && digest.KeyVersion == spec.Lookup.KeyVersion && subtle.ConstantTimeCompare(digest.Sum[:], spec.Lookup.Sum[:]) == 1 {
			matched = true
		}
	}
	return matched
}

// This runs outside SQL before reservation. It authenticates the originally
// issued canonical state and exact stored/request bindings, not current session,
// account, factor or policy authority. Those owners remain mandatory in every
// protected preparation and final link phase. In particular, no successful read
// here can release PKCE or authorize another exchange after an unknown outcome.
func (s *LinkService) authenticateRPCallback(ctx context.Context, r oauth.CallbackRequest, binding rpStartBinding, proofCiphertext []byte, now time.Time) (out rpCallbackFlow, err error) {
	if ctx == nil || s == nil || s.config == nil || s.issuer == nil || r.Validate() != nil || !rpUTCTime(now) {
		return out, identity.InvalidInputError{Field: "oauth_callback_input"}
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if err != nil {
			out.destroy()
			out = rpCallbackFlow{}
		}
	}()
	b := binding.Input.binding()
	p := &rpStartPhase{service: s, input: &binding.Input}
	if binding.Input.Profile != s.profile || b.OperationID != "identity.account.link-start" || b.TenantID != r.TenantID || s.config().Coordinator.AdmissionPolicy == nil || b.PolicyVersion != s.config().Coordinator.AdmissionPolicy.PolicyVersion || r.Origin != s.config().Origin || !reflect.DeepEqual(binding.Provider, r.Callback.Profile()) || p.validateOutputBinding(binding) != nil || now.Before(binding.IssuedAt) || !now.Before(binding.ExpiresAt) {
		return out, identity.ForbiddenError{}
	}
	original, err := p.originalSession()
	if err != nil || !s.ownsSessionBearer(r.TenantID, r.Session, original) {
		return out, identity.ForbiddenError{}
	}
	life, err := original.Lifetime(now)
	if err != nil || !life.Fresh {
		return out, identity.ForbiddenError{}
	}
	// The code stays in its original opaque owner. A matching lookup digest alone
	// cannot substitute another browser's raw state or canonical capability.
	if err := useRPCallbackState(ctx, r.Callback, func(_ context.Context, state []byte) error {
		if !bytes.Equal(state, []byte(binding.State)) {
			return identity.ForbiddenError{}
		}
		return nil
	}); err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		return out, identity.ForbiddenError{}
	}
	aad, err := rpStartBindingAAD(string(b.TenantID), binding.Provider, b.RecordID, binding.StateDigest, "state-proof")
	if err != nil {
		return out, err
	}
	raw, err := s.openRP(ctx, aad, proofCiphertext, 65536)
	if err != nil {
		return out, err
	}
	defer clear(raw)
	out.stateProof, err = capability.ParseProof(string(raw), s.config().Capability.Crypto.Limits)
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	crypto, err := capability.NewService(s.config().Capability.Crypto)
	if err != nil {
		return out, identity.UnavailableError{}
	}
	grant, err := crypto.Verify(ctx, out.stateProof, "identity.oauth.callback", s.config().Capability.Audience)
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if errors.Is(err, capability.ErrInvalidConfiguration) || errors.Is(err, capability.ErrKeyResolution) || errors.Is(err, capability.ErrRevocationUnknown) {
			return out, identity.UnavailableError{}
		}
		return out, identity.ForbiddenError{}
	}
	frame, err := json.Marshal(binding)
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	payload := grant.Payload()
	if len(payload.Caveats) != 1 || !payload.IssuedAt.Equal(binding.IssuedAt) || !payload.ExpiresAt.Equal(binding.ExpiresAt) || grant.Authorize(capability.Use{Issuer: s.config().Capability.Crypto.Issuer, Audience: s.config().Capability.Audience, Subject: string(b.UserID), Tenant: string(b.TenantID), Resource: b.RecordID, Operation: "identity.oauth.callback", Caveats: map[string]string{"identity.oauth.rp.binding": base64.RawURLEncoding.EncodeToString(digest[:])}}) != nil {
		return out, identity.ForbiddenError{}
	}
	plan, err := s.issuer.PrepareOAuthCallbackConsumption(ctx, b, out.stateProof, binding.StateReplayKeyVersion)
	if err != nil {
		return out, err
	}
	if plan.ProofFingerprint != grant.EnvelopeDigest() || !plan.ExpiresAt.Equal(binding.ExpiresAt) {
		return out, identity.ForbiddenError{}
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	out.binding, out.original, out.stateGrant, out.statePlan = binding, original, grant, plan
	return out, nil
}

// Both parser variants retain the original state in their own opaque owner.
// A provider-error callback has no code; never synthesize one to reuse the
// success path or release the stored PKCE verifier.
func useRPCallbackState(ctx context.Context, callback oauth.Callback, consume func(context.Context, []byte) error) error {
	if input, ok := callback.Input(); ok {
		return input.Use(ctx, func(ctx context.Context, _ []byte, state []byte) error { return consume(ctx, state) })
	}
	return callback.UseDeniedState(ctx, consume)
}
