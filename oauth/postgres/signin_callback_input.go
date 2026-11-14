package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// This is authenticated original input, not reservation, provider identity or
// session authority. Only acknowledged coordinator preparation may release PKCE.
type signinCallbackFlow struct {
	binding      signinRPBinding
	original     session.PreAuthTransaction
	stateProof   capability.Proof
	stateGrant   capability.Grant
	statePlan    kernel.CapabilityPlan
	pkce         rpSealedVerifier
	loadedAt     time.Time
	erased       bool
	resultFields []identity.FeatureField
	denied       bool
}

func (f *signinCallbackFlow) destroy() {
	if f == nil {
		return
	}
	_ = f.stateProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	f.stateProof = capability.Proof{}
	clear(f.pkce.ciphertext)
	f.pkce.ciphertext = nil
}

func (s *SigninService) authenticateSigninBrowser(ctx context.Context, r oauth.SigninCallbackRequest, stored signinStoredTransaction, original session.PreAuthTransaction, now time.Time) (out signinCallbackFlow, err error) {
	defer func() {
		if err != nil {
			out.destroy()
			out = signinCallbackFlow{}
		}
	}()
	if ctx == nil || s == nil || r.Validate() != nil || !rpUTCTime(now) || s.config.Coordinator.AdmissionPolicy == nil {
		return out, identity.InvalidInputError{Field: "oauth_signin_callback"}
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	v := stored.Binding
	if !oauth2CallbackMatches(r.Callback, v.OAuth2) {
		return out, identity.ForbiddenError{}
	}
	b := identity.CommandBinding(v.Input.Binding)
	spec, err := original.Bindings()
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	flowSum, err := signinFlowDigest(original)
	if err != nil {
		return out, err
	}
	op := rpSigninStartOperation()
	phase := signinStartPhase{service: s, input: &v.Input, flow: original}
	current, selected := s.profiles[v.Provider.ID]
	if b.ValidateFor(op) != nil || b.TenantID != r.TenantID || b.RecordID != string(b.CommandID) {
		return out, identity.ForbiddenError{}
	}
	sameOriginalFlow := v.Input.Profile == s.profile && v.Input.Flow == flowSum && v.Input.Device == r.Device
	samePolicy := b.PolicyID == s.config.PolicyID && b.PolicyVersion == s.config.Coordinator.AdmissionPolicy.PolicyVersion
	if !sameOriginalFlow || !samePolicy || v.Input.GlobalVersion == 0 || v.Input.TenantVersion == 0 || r.Origin != s.config.Origin {
		return out, identity.ForbiddenError{}
	}
	sameProvider := selected && reflect.DeepEqual(current, v.Provider) && reflect.DeepEqual(r.Callback.Profile(), v.Provider)
	if !sameProvider || phase.validateBinding(v) != nil || now.Before(v.IssuedAt) || !now.Before(v.ExpiresAt) {
		return out, identity.ForbiddenError{}
	}
	browser := signinBrowserScope{Tenant: r.TenantID, FlowID: identity.PreAuthTransactionID(b.AnonymousFlowID), Cookie: r.FlowCookie, Remember: spec.Binding.Intent.Remember, Origin: r.Origin, Callback: v.Input.Callback}
	if checkSigninOriginalBrowser(browser, original, s.config.FlowKeys, b.PolicyID, b.PolicyVersion, now) != nil {
		return out, identity.ForbiddenError{}
	}
	if useRPCallbackState(ctx, r.Callback, func(_ context.Context, state []byte) error {
		if !bytes.Equal(state, []byte(v.State)) {
			return identity.ForbiddenError{}
		}
		return nil
	}) != nil {
		return out, identity.ForbiddenError{}
	}
	out.binding, out.original, out.statePlan = v, original, kernel.CapabilityPlan(stored.State)
	return out, nil
}

func (s *SigninService) authenticateSigninCallback(ctx context.Context, r oauth.SigninCallbackRequest, stored signinStoredTransaction, original session.PreAuthTransaction, ciphertext []byte, now time.Time) (out signinCallbackFlow, err error) {
	out, err = s.authenticateSigninBrowser(ctx, r, stored, original, now)
	if err != nil {
		return out, err
	}
	defer func() {
		if err != nil {
			out.destroy()
			out = signinCallbackFlow{}
		}
	}()
	v := stored.Binding
	b := identity.CommandBinding(v.Input.Binding)
	aad, err := signinBindingAAD(v, "state-proof")
	if err != nil {
		return out, err
	}
	raw, err := s.open(ctx, aad, ciphertext, 65536)
	if err != nil {
		return out, err
	}
	defer clear(raw)
	out.stateProof, err = capability.ParseProof(string(raw), s.config.Capability.Crypto.Limits)
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	crypto, err := capability.NewService(s.config.Capability.Crypto)
	if err != nil {
		return out, identity.UnavailableError{}
	}
	grant, err := crypto.Verify(ctx, out.stateProof, "identity.oauth.callback", s.config.Capability.Audience)
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if errors.Is(err, capability.ErrInvalidConfiguration) || errors.Is(err, capability.ErrKeyResolution) || errors.Is(err, capability.ErrRevocationUnknown) {
			return out, identity.UnavailableError{}
		}
		return out, identity.ForbiddenError{}
	}
	frame, err := json.Marshal(v)
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	payload := grant.Payload()
	if len(payload.Caveats) != 1 || !payload.IssuedAt.Equal(v.IssuedAt) || !payload.ExpiresAt.Equal(v.ExpiresAt) || grant.Authorize(capability.Use{Issuer: s.config.Capability.Crypto.Issuer, Audience: s.config.Capability.Audience, Subject: b.AnonymousFlowID, Tenant: string(b.TenantID), Resource: b.RecordID, Operation: "identity.oauth.callback", Caveats: map[string]string{"identity.oauth.rp.binding": base64.RawURLEncoding.EncodeToString(digest[:])}}) != nil {
		return out, identity.ForbiddenError{}
	}
	plan, err := s.issuer.PrepareOAuthCallbackConsumption(ctx, b, out.stateProof, v.StateReplayKeyVersion)
	if err != nil {
		return out, err
	}
	if plan != kernel.CapabilityPlan(stored.State) || plan.ProofFingerprint != grant.EnvelopeDigest() {
		return out, identity.ForbiddenError{}
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	out.binding, out.original, out.stateGrant, out.statePlan = v, original, grant, plan
	return out, nil
}

func (s *SigninService) loadSigninCallback(ctx context.Context, r oauth.SigninCallbackRequest) (out signinCallbackFlow, err error) {
	if ctx == nil || s == nil || r.Validate() != nil || r.Origin != s.config.Origin {
		return out, identity.InvalidInputError{Field: "oauth_signin_callback"}
	}
	defer func() {
		if err != nil {
			out.destroy()
			out = signinCallbackFlow{}
		}
	}()
	profile := r.Callback.Profile()
	current, ok := s.profiles[profile.ID]
	if !oauth2CallbackMatches(r.Callback, oauth2ProfileDetails(s.oauth2Profiles, profile.ID)) {
		return out, identity.ForbiddenError{}
	}
	if !ok || !reflect.DeepEqual(current, profile) {
		return out, identity.ForbiddenError{}
	}
	var raw []byte
	if err := useRPCallbackState(ctx, r.Callback, func(_ context.Context, state []byte) error {
		var decodeErr error
		raw, decodeErr = base64.RawURLEncoding.Strict().DecodeString(string(state))
		if decodeErr != nil || len(raw) != 32 {
			return identity.ForbiddenError{}
		}
		return nil
	}); err != nil {
		clear(raw)
		return out, identity.ForbiddenError{}
	}
	defer clear(raw)
	versions := make([]int64, 0, len(s.config.StateKeys))
	for v := range s.config.StateKeys {
		versions = append(versions, int64(v))
	}
	slices.Sort(versions)
	digests := make([][]byte, len(versions))
	for i, v := range versions {
		sum := rpStateDigest(s.config.StateKeys[uint32(v)], uint32(v), r.TenantID, profile.ID, raw)
		digests[i] = sum[:]
	}
	var started time.Time
	if s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&started) != nil {
		return out, identity.UnavailableError{}
	}
	rows, err := s.pool.Raw().Query(ctx, `SELECT t.transaction_id,t.origin_command_id,t.preauth_id,t.pkce_key_version,t.pkce_commitment,t.pkce_ciphertext,t.state_proof_ciphertext,t.binding_ciphertext,t.state_key_version,t.state_digest,t.issued_at,t.expires_at,t.version::text,t.secrets_erased_at
 FROM `+rpQuotedSchema(s.config.Schema)+`.transactions t JOIN unnest($3::bigint[],$4::bytea[]) AS selected(key_version,digest) ON t.state_key_version=selected.key_version AND t.state_digest=selected.digest
 WHERE t.tenant_id=$1 AND t.provider_id=$2 AND t.configuration_version=$5::numeric AND t.issuer=$6 AND t.client_id=$7 AND t.redirect_uri=$8 AND t.response_mode='query' AND t.operation='identity.oauth.signin-start' AND t.user_id IS NULL AND t.session_id IS NULL AND t.preauth_id IS NOT NULL LIMIT 2`, string(r.TenantID), profile.ID, versions, digests, profile.Version, profile.Issuer, profile.ClientID, profile.RedirectURI)
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
	var transaction, flowID, version string
	var origin, commitment, pkce, proof, wire, digest []byte
	var pkceVersion, stateVersion uint32
	var issued, expires time.Time
	var erased *time.Time
	if rows.Scan(&transaction, &origin, &flowID, &pkceVersion, &commitment, &pkce, &proof, &wire, &stateVersion, &digest, &issued, &expires, &version, &erased) != nil || rows.Next() || rows.Err() != nil {
		return out, identity.UnavailableError{}
	}
	rows.Close()
	var now time.Time
	if s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now) != nil {
		return out, identity.UnavailableError{}
	}
	started, now = started.UTC(), now.UTC()
	active := version == "1" && erased == nil && pkce != nil && proof != nil
	terminal := version == "2" && erased != nil && pkce == nil && proof == nil
	if len(digest) != 32 || len(commitment) != 32 || len(origin) != 16 || now.Before(started) || !now.Before(started.Add(20*time.Second)) || now.Before(issued) || !now.Before(expires) || (!active && !terminal) {
		return out, identity.ForbiddenError{}
	}
	probe := signinRPBinding{Input: signinStartInput{Binding: rpStoredBinding{TenantID: r.TenantID, RecordID: transaction, OperationID: "identity.oauth.signin-start"}}, Provider: profile, StateDigest: [32]byte(digest)}
	stored, err := s.openSigninTransaction(ctx, probe, wire)
	if err != nil {
		return out, err
	}
	b := identity.CommandBinding(stored.Binding.Input.Binding)
	commandID, decodeErr := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	v := stored.Binding
	if decodeErr != nil || !bytes.Equal(commandID, origin) || b.TenantID != r.TenantID || b.RecordID != transaction || b.AnonymousFlowID != flowID || v.StateKeyVersion != stateVersion || v.PKCEKeyVersion != pkceVersion || !bytes.Equal(v.PKCECommitment[:], commitment) || !v.IssuedAt.Equal(issued) || !v.ExpiresAt.Equal(expires) {
		return out, identity.ForbiddenError{}
	}
	original, err := sessionpg.ReadPreAuth(ctx, s.pool.Raw(), s.config.Session, r.TenantID, identity.PreAuthTransactionID(flowID))
	if err != nil {
		return out, err
	}
	// Include the browser read in the original primary-observation budget.
	// Sampling again must not restart that budget or the RP lifetime.
	if s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now) != nil {
		return out, identity.UnavailableError{}
	}
	now = now.UTC()
	if now.Before(started) || !now.Before(started.Add(20*time.Second)) {
		return out, identity.ForbiddenError{}
	}
	if terminal {
		if (!stored.Denied && len(stored.ResultFields) < 1) || len(stored.ResultFields) > 128 || (stored.Denied && len(stored.ResultFields) != 0) {
			return out, identity.ForbiddenError{}
		}
		out, err = s.authenticateSigninBrowser(ctx, r, stored, original, now)
		if err != nil {
			return out, err
		}
		out.erased, out.resultFields, out.loadedAt = true, stored.ResultFields, started
		out.denied = stored.Denied
		return out, nil
	}
	if len(stored.ResultFields) != 0 || stored.Denied {
		return out, identity.ForbiddenError{}
	}
	out, err = s.authenticateSigninCallback(ctx, r, stored, original, proof, now)
	if err != nil {
		return out, err
	}
	out.pkce = rpSealedVerifier{ciphertext: bytes.Clone(pkce), commitment: v.PKCECommitment, keyVersion: pkceVersion}
	out.loadedAt = started
	return out, nil
}

// SigninCallbackRateSource authenticates original state/browser attribution for
// a transport provider budget. It does not reserve state, release PKCE, exchange
// a code, issue a session or confer admission. Callback must repeat its current
// native fences. Caller retains and subsequently destroys Callback custody.
func (s *SigninService) SigninCallbackRateSource(ctx context.Context, r oauth.SigninCallbackRequest) (out oauth.CallbackRateContext, err error) {
	if ctx == nil || s == nil {
		return oauth.CallbackRateContext{}, identity.InvalidInputError{Field: "oauth_signin_callback"}
	}
	ctx, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out, err = oauth.CallbackRateContext{}, identity.UnavailableError{}
		}
	}()
	flow, err := s.loadSigninCallback(ctx, r)
	if err != nil {
		return oauth.CallbackRateContext{}, err
	}
	defer flow.destroy()
	return oauth.CallbackRateContext{ProviderID: flow.binding.Provider.ID, TransactionID: flow.binding.Input.Binding.RecordID, Lifetime: flow.binding.ExpiresAt.Sub(flow.binding.IssuedAt)}, nil
}
