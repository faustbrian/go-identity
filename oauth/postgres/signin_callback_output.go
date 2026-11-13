package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Only authenticated provider expiry, tokenless account/session projections and
// original admission custody are retained. The session bearer/CSRF remain with
// this invocation's SessionIssuer preparation; restoration cannot recreate them.
type signinCallbackOutput struct {
	Schema            uint8
	Fields            []identity.FeatureField
	ProviderExpiresAt time.Time
	Admission         signinStoredAdmission
	ReadStarted       time.Time
	TerminalBinding   []byte
}

func (p *signinCallbackPhase) outputAAD(generation uint64) (envelope.Context, error) {
	if generation == 0 || p == nil || p.service == nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	f, ok := p.original.Feature()
	if !ok {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	frame, err := json.Marshal(struct {
		Original   identity.FeatureCommandSpec
		Generation uint64
		Profile    [32]byte
	}{f, generation, p.service.profile})
	if err != nil {
		return envelope.Context{}, err
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-oauth-signin-callback-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *signinCallbackPhase) generate(ctx context.Context, generation uint64, admission risk.AuthenticationAdmission) ([]byte, error) {
	if generation == 0 || p.prepared != (session.PreparedIssuance{}) || p.authenticatedAt.IsZero() {
		return nil, identity.ForbiddenError{}
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	s, v := p.service.start, p.flow.binding
	var now time.Time
	if s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now) != nil {
		return nil, identity.UnavailableError{}
	}
	if err := p.checkBrowser(now.UTC()); err != nil {
		return nil, err
	}
	b := v.Input.Binding
	verifierBinding, err := newRPVerifierBinding(string(b.TenantID), v.Provider, b.RecordID, v.StateDigest, b.OperationID)
	if err != nil {
		return nil, err
	}
	verifier, err := s.verifiers.open(ctx, verifierBinding, p.flow.pkce, v.IssuedAt, v.ExpiresAt, now.UTC())
	if err != nil {
		return nil, err
	}
	defer verifier.Destroy()
	if verifier.Challenge() != v.Challenge {
		return nil, identity.ForbiddenError{}
	}
	provider, ok := s.providers.Lookup(v.Provider.ID)
	if !ok || !reflect.DeepEqual(provider.Profile(), v.Provider) {
		return nil, identity.ForbiddenError{}
	}
	input, ok := p.request.Callback.Input()
	if !ok {
		return nil, identity.ForbiddenError{}
	}
	// Only FeaturePreparationAdmission.Generate reaches this exchange after
	// acknowledged one-use state reservation. No primary Work/lock is retained.
	result, err := provider.Exchange(ctx, input, verifier, v.Nonce)
	defer result.Tokens.Destroy()
	if err != nil {
		return nil, err
	}
	verified := result.Identity
	if verified.ProviderID() != v.Provider.ID || verified.Issuer() != v.Provider.Issuer || verified.Subject() == "" {
		return nil, identity.ForbiddenError{}
	}
	account, err := s.directory.GetProviderSigninAccount(ctx, kernel.ProviderSigninAccountQuery{TenantID: b.TenantID, Provider: verified.ProviderID(), Issuer: verified.Issuer(), Subject: verified.Subject()})
	if err != nil {
		return nil, err
	}
	factors, err := mfapg.ReadOAuthSigninFactors(ctx, s.pool, b.TenantID, account.Account.UserID, s.config.MaximumDuration)
	if err != nil {
		return nil, err
	}
	directory, err := s.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.config.GlobalAuthorityID, TenantID: b.TenantID})
	if err != nil {
		return nil, err
	}
	if !directory.Enabled || directory.GlobalVersion != v.Input.GlobalVersion || directory.TenantVersion != v.Input.TenantVersion {
		return nil, identity.ForbiddenError{}
	}
	policy, err := p.service.policy.Get(ctx, authoritypg.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), SubjectID: authorization.SubjectID(account.Account.UserID), PolicyNamespace: p.service.config.PolicyNamespace})
	if err != nil {
		return nil, err
	}
	if s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now) != nil {
		return nil, identity.UnavailableError{}
	}
	now = now.UTC()
	if err := p.checkBrowser(now); err != nil {
		return nil, err
	}
	if err := admission.CheckAt(ctx, now); err != nil {
		return nil, err
	}
	until := verified.IDTokenExpiresAt()
	if deadline := p.flow.loadedAt.Add(20 * time.Second); deadline.Before(until) {
		until = deadline
	}
	if v.ExpiresAt.Before(until) {
		until = v.ExpiresAt
	}
	if !until.After(now) {
		return nil, identity.ForbiddenError{}
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		return nil, err
	}
	family, err := identity.NewSubjectID()
	if err != nil {
		return nil, err
	}
	authority, err := p.authority(account, factors.Version(), policy.Version, string(id), string(family))
	if err != nil {
		return nil, err
	}
	f, _ := p.original.Feature()
	flow, _ := p.flow.original.Bindings()
	// Proof is structural provenance for this verified native provider result,
	// not an opaque caller-issued authentication proof. The original provider
	// configuration version and exact credential generation stay independent.
	proof := auth.Proof{ID: auth.ProofID(f.Binding.CommandID), Tenant: string(b.TenantID), Subject: string(account.Account.UserID), Method: "oauth", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: p.service.config.Audience, IssuedAt: now, ExpiresAt: until}
	p.prepared, err = p.issuer.PrepareOAuth(f.Binding, session.SessionSpec{SessionID: string(id), FamilyID: string(family), TenantID: b.TenantID, UserID: account.Account.UserID, Audience: p.service.config.Audience, Version: 1, FamilyVersion: 1, Remember: flow.Binding.Intent.Remember, Authority: authority, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: proof, ProofVersion: v.Provider.Version, CredentialID: string(account.Credential.Credential.ID), CredentialVersion: account.Credential.Credential.Version}, IssuedAt: now, LastActivityAt: now})
	if err != nil {
		return nil, err
	}
	record, ok := p.prepared.Session()
	if !ok {
		return nil, identity.UnavailableError{}
	}
	fields, err := sessionpg.OAuthSigninSessionFields(record)
	if err != nil {
		return nil, err
	}
	accountFields, err := kernel.OAuthSigninAccountFields(account)
	if err != nil {
		return nil, err
	}
	fields = append(fields, accountFields...)
	terminalAAD, err := signinBindingAAD(v, "binding")
	if err != nil {
		return nil, err
	}
	terminalPlain, err := json.Marshal(signinStoredTransaction{Binding: v, State: rpStoredGrant(p.flow.statePlan), ResultFields: fields})
	if err != nil {
		return nil, err
	}
	defer clear(terminalPlain)
	terminal, err := s.seal(ctx, terminalAAD, terminalPlain)
	if err != nil {
		return nil, err
	}
	defer clear(terminal)
	plain, err := json.Marshal(signinCallbackOutput{Schema: 1, Fields: fields, ProviderExpiresAt: verified.IDTokenExpiresAt(), Admission: signinStoredAdmission(admission.Prepared()), ReadStarted: p.flow.loadedAt, TerminalBinding: terminal})
	if err != nil || len(plain) > 128<<10 {
		return nil, identity.UnavailableError{}
	}
	defer clear(plain)
	return s.seal(ctx, aad, plain)
}

func (p *signinCallbackPhase) authority(account kernel.ProviderAccountAdmission, factor, policy uint64, id, family string) (session.AuthoritySnapshot, error) {
	q := kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.service.start.config.GlobalAuthorityID, TenantID: account.Account.TenantID}
	user := account.Account.UserID
	keys, err := kernel.KernelAuthorityKeys(q, user)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	skeys, err := sessionpg.SessionAuthorityKeys(q.TenantID, user, family, id)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	scope := authoritypg.AuthorityScope{TenantID: authorization.TenantID(q.TenantID), SubjectID: authorization.SubjectID(user), PolicyNamespace: p.service.config.PolicyNamespace}
	key, err := scope.Key()
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	factorKey, err := mfapg.FactorAuthorityKey(q.TenantID, user)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	bind := func(k string, v uint64) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: k, Version: v}
	}
	frozen, credential := p.flow.binding.Input, account.Credential
	return session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: bind(keys.Global, frozen.GlobalVersion), Tenant: bind(keys.Tenant, frozen.TenantVersion), User: bind(keys.User, credential.UserAuthorityVersion), Identifier: bind(keys.Identifier, credential.IdentifierAuthorityVersion), Credential: bind(keys.Credential, credential.CredentialAuthorityVersion), SessionFamily: bind(skeys.Family, 1), Session: bind(skeys.Session, 1), Authorization: bind(key, policy), Factor: session.OptionalAuthorityBinding{Present: true, Binding: bind(factorKey, factor)}})
}

func (p *signinCallbackPhase) restore(ctx context.Context, generation uint64, wire []byte) (*signinExecution, identity.Command, error) {
	deny := func() (*signinExecution, identity.Command, error) {
		return nil, identity.Command{}, identity.ForbiddenError{}
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, identity.Command{}, err
	}
	plain, err := p.service.start.open(ctx, aad, wire, 192<<10)
	if err != nil {
		return nil, identity.Command{}, err
	}
	defer clear(plain)
	var stored signinCallbackOutput
	if decodeRPOutput(plain, &stored) != nil || stored.Schema != 1 || len(stored.Fields) < 1 || len(stored.Fields) > 128 || !rpUTCTime(stored.ProviderExpiresAt) || !rpUTCTime(stored.ReadStarted) || stored.ReadStarted.Before(p.flow.binding.IssuedAt) {
		return deny()
	}
	for _, field := range stored.Fields {
		if !strings.HasPrefix(field.Name, "session.result.") && !strings.HasPrefix(field.Name, "oauth.signin.account.") {
			return deny()
		}
	}
	f, _ := p.original.Feature()
	f.Fields = append(f.Fields, stored.Fields...)
	command, err := identity.NewFeaturePreAuthCommand(f, p.request.FlowCookie)
	if err != nil {
		return deny()
	}
	record, err := sessionpg.OAuthSigninSession(command)
	if err != nil {
		return deny()
	}
	account, err := kernel.OAuthSigninAccount(command)
	if err != nil {
		return deny()
	}
	fields, err := sessionpg.OAuthSigninSessionFields(record)
	if err != nil {
		return deny()
	}
	accountFields, err := kernel.OAuthSigninAccountFields(account)
	if err != nil {
		return deny()
	}
	if !sameRPFields(append(fields, accountFields...), stored.Fields) {
		return deny()
	}
	spec, err := record.Bindings()
	if err != nil {
		return deny()
	}
	v := p.flow.binding
	if account.Account.Provider != v.Provider.ID || account.Account.Issuer != v.Provider.Issuer || account.Account.UserID != spec.UserID || spec.TenantID != p.request.TenantID || spec.Audience != p.service.config.Audience || spec.Authentication.ProofVersion != v.Provider.Version || spec.Authentication.CredentialID != string(account.Credential.Credential.ID) || spec.Authentication.CredentialVersion != account.Credential.Credential.Version {
		return deny()
	}
	proof := spec.Authentication.Proof
	if spec.IssuedAt.Before(stored.ReadStarted) || proof.ExpiresAt.After(stored.ProviderExpiresAt) || proof.ExpiresAt.After(v.ExpiresAt) || proof.ExpiresAt.After(stored.ReadStarted.Add(20*time.Second)) {
		return deny()
	}
	terminal, err := p.service.start.openSigninTransaction(ctx, v, stored.TerminalBinding)
	if err != nil || !reflect.DeepEqual(terminal.Binding, v) || kernel.CapabilityPlan(terminal.State) != p.flow.statePlan || !sameRPFields(terminal.ResultFields, stored.Fields) {
		return deny()
	}
	flow, err := p.flow.original.Bindings()
	if err != nil {
		return deny()
	}
	remember, err := spec.Remember.Bindings()
	originalRemember, e := flow.Binding.Intent.Remember.Bindings()
	if err != nil || e != nil || remember != originalRemember {
		return deny()
	}
	vector, err := spec.Authority.Bindings()
	if err != nil {
		return deny()
	}
	authority, err := p.authority(account, vector.Factor.Binding.Version, vector.Authorization.Version, spec.SessionID, spec.FamilyID)
	if err != nil {
		return deny()
	}
	expected, err := authority.Bindings()
	if err != nil || expected != vector {
		return deny()
	}
	scope, subject := p.riskScope()
	admission, err := p.service.start.custody.Restore(ctx, risk.PreparedAuthenticationAdmission(stored.Admission), scope, subject)
	if err != nil {
		return nil, identity.Command{}, err
	}
	if p.prepared != (session.PreparedIssuance{}) {
		original, ok := p.prepared.Session()
		if !ok {
			return deny()
		}
		originalFields, err := sessionpg.OAuthSigninSessionFields(original)
		if err != nil || !sameRPFields(originalFields, fields) {
			return deny()
		}
	}
	return &signinExecution{record: record, account: account, admission: admission, generation: generation, digest: sha256.Sum256(wire), readStarted: stored.ReadStarted, terminalBinding: stored.TerminalBinding}, command, nil
}
