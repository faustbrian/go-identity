package mfapostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/jackc/pgx/v5"
)

// TOTPURIConfig explicitly selects the original-session synchronizer adapter
// and exact HTTPS origins. No route is registered. All owners and key custody
// are borrowed from the configured enrollment service; keep them alive until
// calls drain. The same original configuration must remain available on retry.
// The account label prefers the verified primary email. With no such primary,
// exactly one verified email may label the URI; multiple candidates deny.
// Selecting a display label never makes that identifier primary or recovery
// authority. Its value, version and primary status are bound and fenced.
type TOTPURIConfig struct {
	Primary        TOTPURIPrimarySource
	AllowedOrigins []string
	// Nil preserves initial-enrollment-only provenance and configuration bytes.
	Replacement *TOTPReplacementContinuationConfig
}

// TOTPURIService atomically consumes pending enrollment disclosure through the
// existing command/preparation/risk/audit/lifecycle owners. It creates no secret,
// proof, successor enrollment, goroutine or private transaction. Install
// URIRevealMigrationSource first. Concurrent immutable calls are supported.
type TOTPURIService struct{ state func() *totpURIState }
type totpURIState struct {
	enrollment *totpEnrollmentState
	config     TOTPURIConfig
	identity   [32]byte
}

var _ mfa.TOTPURIService = (*TOTPURIService)(nil)

// NewTOTPURIService freezes explicit composition without IO or generation.
// Missing primary/CSRF ownership, protected risk classification or origin policy
// denies setup; no bearer-only or unclassified-risk fallback is permitted.
func NewTOTPURIService(enrollment *TOTPEnrollmentService, c TOTPURIConfig) (*TOTPURIService, error) {
	if enrollment == nil || enrollment.state == nil || nilEnrollmentPrimary(c.Primary) || len(c.AllowedOrigins) < 1 || len(c.AllowedOrigins) > 16 {
		return nil, invalidEnrollment()
	}
	s := &totpURIState{enrollment: enrollment.state(), config: c}
	if c.Replacement != nil {
		selected := *c.Replacement
		if selected.Management == nil || selected.Management.state == nil || nilEnrollmentPrimary(selected.Primary) || selected.Management.state().shared != s.enrollment || !selected.Management.ReplacementConfigured() {
			return nil, invalidEnrollment()
		}
		s.config.Replacement = &selected
	}
	s.config.AllowedOrigins = slices.Clone(c.AllowedOrigins)
	slices.Sort(s.config.AllowedOrigins)
	for i, origin := range s.config.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || len(origin) > 2048 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != origin || i > 0 && origin == s.config.AllowedOrigins[i-1] {
			return nil, invalidEnrollment()
		}
	}
	profile, err := s.enrollment.config.Counters.CommandCounters.Policy.Admit("identity.mfa.totp-uri")
	if err != nil || profile.Profile.Class != risk.CredentialMutation {
		return nil, invalidEnrollment()
	}
	frame := append(slices.Clone(s.enrollment.identity[:]), []byte("mfa-uri-v1\x00")...)
	for _, origin := range s.config.AllowedOrigins {
		frame = append(frame, []byte(origin+"\x00")...)
	}
	if s.config.Replacement != nil {
		identity := s.config.Replacement.Management.state().identity
		frame = append(frame, []byte("replacement\x00")...)
		frame = append(frame, identity[:]...)
	}
	s.identity = sha256.Sum256(frame)
	clear(frame)
	return &TOTPURIService{state: func() *totpURIState { return s }}, nil
}

func uriOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.totp-uri", SchemaID: "mfa-totp-uri", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// TotpUriRateSource authenticates original enrollment/session/CSRF custody and
// reads its immutable quota lifetime and earliest disclosure deadline. It uses
// the same retained native input as TotpUri, without decrypting the TOTP secret,
// comparison, generation, reservation, debit or reveal consumption. Returned
// metadata is not mutation permission. The transport must retain this original
// deadline; a later source read cannot renew it. Native mutation independently
// fences current authority. Unsupported, expired or foreign custody denies.
func (s *TOTPURIService) TotpUriRateSource(ctx context.Context, r mfa.TotpUriRequest) (lifetime time.Duration, until time.Time, err error) {
	if ctx == nil || s == nil || s.state == nil || r.Validate() != nil {
		return 0, time.Time{}, invalidEnrollment()
	}
	state := s.state()
	if !slices.Contains(state.config.AllowedOrigins, r.Origin) {
		return 0, time.Time{}, identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, state.enrollment.config.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			lifetime, until = 0, time.Time{}
		}
	}()
	p := &totpURIPhase{state: state, request: r}
	defer p.destroy()
	if err = p.load(ctx); err != nil {
		return 0, time.Time{}, err
	}
	if err = p.refreshPrimary(ctx); err != nil {
		return 0, time.Time{}, err
	}
	until, err = p.deadline()
	if err != nil {
		return 0, time.Time{}, err
	}
	m := p.pending.metadata()
	if m.ExpiresAt.Before(until) {
		until = m.ExpiresAt
	}
	lifetime = m.ExpiresAt.Sub(m.CreatedAt)
	if lifetime <= 0 || !time.Now().Before(until) {
		return 0, time.Time{}, identity.ForbiddenError{}
	}
	return lifetime, until, nil
}

// TotpUri binds the original enrollment/session to one separate stable command,
// admits current owners and protected risk, and returns material only from an
// error-free first committed reveal. Matching retries and recovery return none.
// Unknown outcomes never reveal or allocate a successor. Earlier cancellation
// wins; caller-owned borrowed input must remain immutable until return.
func (s *TOTPURIService) TotpUri(ctx context.Context, r mfa.TotpUriRequest) (out mfa.TotpUriResult, err error) {
	if ctx == nil || s == nil || s.state == nil || r.Validate() != nil {
		return out, invalidEnrollment()
	}
	state := s.state()
	if !slices.Contains(state.config.AllowedOrigins, r.Origin) {
		return out, identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, state.enrollment.config.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out.URI = mfa.RevealOnceURI{}
		}
	}()
	p := &totpURIPhase{state: state, request: r}
	defer p.destroy()
	if err = p.load(ctx); err != nil {
		return out, err
	}
	c, registry, err := state.enrollment.coordinator(p)
	if err != nil {
		return out, err
	}
	p.coordinator, p.registry = c, registry
	if err = p.buildCommand(); err != nil {
		return out, err
	}
	result, err := c.ExecutePreparedFeature(ctx, p.command, p.plan)
	out.Outcome = result.Outcome
	if err == nil && result.Outcome == identity.CommitOutcomeCommitted && p.applied && p.output != nil {
		out.URI = mfa.RevealOnceURI{URI: p.output.URI, EnrollmentID: r.EnrollmentID}
	}
	return out, err
}

// RecoverTotpUri reconciles exact secret-free historical scope under current
// result-access policy. It never restores possession, decrypts a factor, reveals
// material or repeats consumption; every native participant must agree.
func (s *TOTPURIService) RecoverTotpUri(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out mfa.TotpUriResult, err error) {
	if ctx == nil || s == nil || s.state == nil || q.OperationID != uriOperation().OperationID {
		return out, invalidEnrollment()
	}
	state := s.state()
	ctx, cancel := context.WithTimeout(ctx, state.enrollment.config.MaximumDuration)
	defer cancel()
	p := &totpURIPhase{state: state}
	c, _, err := state.enrollment.coordinator(p)
	if err != nil {
		return out, err
	}
	receipt, err := c.RecoverFeatureCommand(ctx, q, caller)
	out.Outcome = receipt.Outcome
	return out, err
}

type totpURIPending struct {
	Input            totpEnrollmentInput
	Replacement      *factorUpdateInput
	Wire             []byte
	RowVersion       uint64
	Label, LabelID   string
	LabelVersion     uint64
	LabelPrimary     bool
	AuthorityVersion uint64
}

func (p *totpURIPending) metadata() PendingTOTPMetadata {
	if p.Replacement != nil {
		return *p.Replacement.Replacement
	}
	return p.Input.Meta
}

func (p *totpURIPending) binding() identity.CommandBinding {
	if p.Replacement != nil {
		return p.Replacement.Binding
	}
	return p.Input.Binding
}

func (p *totpURIPhase) load(ctx context.Context) error {
	r := p.request
	s := p.state.enrollment
	var parent, wire, fingerprint, secret []byte
	var keyVersion int64
	var rowVersion, beforeVersion string
	var revealed bool
	var purpose string
	var revealID []byte
	replacementPurpose := enrollmentOperation().OperationID
	if p.state.config.Replacement != nil {
		replacementPurpose = factorUpdateOperation().OperationID
	}
	projection := `f.reveal_consumed,f.reveal_command_id,COALESCE(f.reveal_before_version::text,'')`
	if p.confirmation != nil {
		projection = `f.activation_command_id IS NOT NULL,f.activation_command_id,COALESCE(f.activation_before_version::text,'')`
	}
	// Only closed owner-selected projections vary; caller data stays parameterized.
	err := s.pool.Raw().QueryRow(ctx, `SELECT f.created_command_id,f.row_version::text,f.created_purpose,`+projection+`,
CASE WHEN octet_length(f.encrypted_secret)<=4096 THEN f.encrypted_secret ELSE ''::bytea END,
k.fingerprint,k.fingerprint_key_version,CASE WHEN octet_length(k.request_preparation_ciphertext)<=$6 THEN k.request_preparation_ciphertext ELSE ''::bytea END
FROM identity_mfa.totp_factors f JOIN identity.request_key_mappings k ON k.command_id=f.created_command_id AND k.tenant_id=f.tenant_id
JOIN identity.commands c ON c.command_id=f.created_command_id AND c.tenant_id=f.tenant_id AND c.purpose=f.created_purpose
WHERE f.tenant_id=$1 AND f.user_id=$2 AND f.factor_id=$3 AND f.state IN(1,2) AND f.created_purpose IN($5,$7) AND c.state='committed'
AND k.namespace=$4 AND k.actor_id=f.user_id AND k.actor_kind='user' AND k.method='POST' AND k.route_id=f.created_purpose`, string(r.TenantID), string(r.Caller.Request.Subject.ID), string(r.EnrollmentID), s.config.RequestKeys.Namespace, enrollmentOperation().OperationID, maximumEnrollmentCustody, replacementPurpose).Scan(&parent, &rowVersion, &purpose, &revealed, &revealID, &beforeVersion, &secret, &fingerprint, &keyVersion, &wire)
	defer clear(wire)
	defer clear(secret)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return identity.ForbiddenError{}
		}
		return enrollmentReadError(ctx)
	}
	if revealed {
		if base64.RawURLEncoding.EncodeToString(revealID) != string(r.CommandID) {
			return identity.ForbiddenError{}
		}
		rowVersion = beforeVersion
	}
	version, err := strconv.ParseUint(rowVersion, 10, 64)
	if err != nil || version == 0 || len(fingerprint) != 32 || keyVersion < 1 || keyVersion > 4294967295 || len(secret) == 0 {
		return invalidEnrollment()
	}
	parentID, err := identity.ParseCommandID(base64.RawURLEncoding.EncodeToString(parent))
	if err != nil {
		return invalidEnrollment()
	}
	op := enrollmentOperation()
	if purpose == factorUpdateOperation().OperationID {
		op = factorUpdateOperation()
	}
	k := kernel.RequestKeyPreparationBinding{Namespace: s.config.RequestKeys.Namespace, Scope: kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}, Admission: kernel.RequestKeyAdmission{CommandID: parentID, FingerprintKeyVersion: uint32(keyVersion)}, Feature: kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, PolicyVersion: s.config.RequestKeys.Policy.PolicyVersion, IntentDigest: [32]byte(fingerprint)}
	codec := &totpEnrollmentPhase{state: s}
	var aad envelope.Context
	if op == factorUpdateOperation() {
		aad, err = (&factorUpdatePhase{state: p.state.config.Replacement.Management.state()}).inputAAD(k)
	} else {
		aad, err = codec.inputAAD(k)
	}
	if err != nil {
		return err
	}
	plain, err := codec.open(ctx, aad, wire)
	if err != nil {
		return err
	}
	defer clear(plain)
	if op == factorUpdateOperation() {
		err = p.restoreReplacementParent(ctx, k, plain, secret, version)
	} else {
		var input totpEnrollmentInput
		if decodeEnrollmentJSON(plain, &input) != nil || input.Schema != 1 || input.Binding.CommandID != parentID || input.Binding.TenantID != r.TenantID || input.Binding.UserID != identity.UserID(r.Caller.Request.Subject.ID) || input.Binding.RecordID != string(r.EnrollmentID) || input.Meta.FactorID != string(r.EnrollmentID) || input.Meta.Profile != s.config.Profile {
			clear(input.Primary)
			return invalidEnrollment()
		}
		p.pending = &totpURIPending{Input: input, Wire: slices.Clone(secret), RowVersion: version}
		if p.confirmation != nil {
			p.primary, err = p.confirmation.primary.RestoreEnrollmentForConfirmation(ctx, p.confirmRequest, parentID, version, input.Primary)
		} else {
			p.primary, err = p.state.config.Primary.RestoreEnrollmentForURI(ctx, r, parentID, version, input.Primary)
		}
	}
	if err != nil {
		return err
	}
	// Native preparation fences authority before its generation callback. Read
	// once outside those locks. An exact retained reveal/activation candidate
	// may instead reconstruct historical intent after intentional revocation;
	// the coordinator still authenticates that complete command and outcome.
	if !revealed {
		if err := p.refreshPrimary(ctx); err != nil {
			return err
		}
	}
	if p.confirmation != nil {
		var authority string
		err = s.pool.Raw().QueryRow(ctx, `SELECT CASE WHEN f.activation_command_id IS NULL THEN a.version ELSE f.activation_authority_before END::text FROM identity_mfa.totp_factors f JOIN identity_mfa.factor_authorities a ON a.tenant_id=f.tenant_id AND a.user_id=f.user_id WHERE f.tenant_id=$1 AND f.user_id=$2 AND f.factor_id=$3`, string(r.TenantID), string(p.pending.binding().UserID), string(r.EnrollmentID)).Scan(&authority)
		if err != nil {
			return enrollmentReadError(ctx)
		}
		p.pending.AuthorityVersion, err = strconv.ParseUint(authority, 10, 64)
		if err != nil || p.pending.AuthorityVersion == 0 {
			return invalidEnrollment()
		}
		return nil
	}
	// Registration verification does not select a primary address. Its sole
	// verified address can label a factor without acquiring primary authority.
	rows, err := s.pool.Raw().Query(ctx, `SELECT identifier_id,canonical_value,version::text,is_primary FROM identity.identifiers i WHERE tenant_id=$1 AND user_id=$2 AND verified AND verification_state=2 AND kind='email' AND (is_primary OR NOT EXISTS(SELECT 1 FROM identity.identifiers p WHERE p.tenant_id=i.tenant_id AND p.user_id=i.user_id AND p.verified AND p.verification_state=2 AND p.is_primary AND p.kind='email')) ORDER BY identifier_id LIMIT 2`, string(r.TenantID), string(p.pending.binding().UserID))
	if err != nil {
		return enrollmentReadError(ctx)
	}
	defer rows.Close()
	var labelVersion string
	if !rows.Next() || rows.Scan(&p.pending.LabelID, &p.pending.Label, &labelVersion, &p.pending.LabelPrimary) != nil || rows.Next() || rows.Err() != nil {
		return identity.ForbiddenError{}
	}
	p.pending.LabelVersion, err = strconv.ParseUint(labelVersion, 10, 64)
	if err != nil || p.pending.LabelVersion == 0 {
		return invalidEnrollment()
	}
	return nil
}

// Format prevents implicit traversal of native owners and configuration.
func (TOTPURIService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.TOTPURIService(redacted)"))
}

// MarshalJSON denies implicit runtime export.
func (TOTPURIService) MarshalJSON() ([]byte, error) { return nil, invalidEnrollment() }

// MarshalText denies implicit runtime export.
func (TOTPURIService) MarshalText() ([]byte, error) { return nil, invalidEnrollment() }

// Format redacts borrowed primary ownership and deployment configuration.
func (TOTPURIConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.TOTPURIConfig(redacted)"))
}

// MarshalJSON denies implicit native configuration export.
func (TOTPURIConfig) MarshalJSON() ([]byte, error) { return nil, invalidEnrollment() }

// MarshalText denies implicit native configuration export.
func (TOTPURIConfig) MarshalText() ([]byte, error) { return nil, invalidEnrollment() }
