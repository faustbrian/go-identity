package mfapostgres

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// TOTPEnrollmentPrimaryAdmission is the narrow consumer-owned boundary for a
// real configured primary adapter. Password's native source implements it
// without making MFA depend on password/session storage. Consume must fence
// current primary owners and use original proof once in this same Work; Check
// must recheck original freshness after waits. An application-written no-op is
// not an authentication adapter. Browser CSRF/origin and risk remain required.
type TOTPEnrollmentPrimaryAdmission interface {
	Consume(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command) error
	Check(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command) error
}

// TOTPEnrollmentPreparation is trusted native generation input, never a client
// DTO. AuthorityVersion is the actual known-empty factor generation selected
// during admission. CreatedAt is the original UTC-compatible database instant,
// at microsecond precision; TTL is 1 second..15 minutes at that precision.
// IDs/profile/TTL must enter original command custody before generation.
type TOTPEnrollmentPreparation struct {
	TenantID         identity.TenantID
	UserID           identity.UserID
	FactorID         string
	AuthorityVersion uint64
	Profile          mfa.TOTPProfile
	CreatedAt        time.Time
	TTL              time.Duration
}

// PendingTOTPMetadata is an immutable non-secret preparation projection. It is
// not proof of persistence, active enrollment or current account authority.
type PendingTOTPMetadata struct {
	TenantID             identity.TenantID
	UserID               identity.UserID
	FactorID             string
	AuthorityVersion     uint64
	Profile              mfa.TOTPProfile
	CreatedAt, ExpiresAt time.Time
}

type preparedTOTPEnrollment struct {
	metadata PendingTOTPMetadata
	wire     []byte
	binding  envelope.Context
}

// PreparedTOTPEnrollment retains only encrypted factor custody behind an
// immutable closure. Copies share owned immutable bytes; returned envelopes and
// scalar fields cannot change them. It grants no primary admission, disclosure,
// transaction or activation. Zero denies. Destroy transient plaintext after use.
type PreparedTOTPEnrollment struct{ custody func() preparedTOTPEnrollment }

// TOTPEnrollmentPreparer borrows a local keyring and owns no IO, clock, pool,
// goroutine or retry authority. Generate outside protected database locks.
// Concurrent calls are safe under the keyring's contract. Retain decrypting keys
// through pending enrollments, journal recovery and their retention policy.
type TOTPEnrollmentPreparer struct {
	crypto *envelope.Service
	key    string
}

// NewTOTPEnrollmentPreparer configures local encryption without generating a
// secret or touching storage. No remote key provider or application callback
// can be selected in this profile. Key presence is checked during generation.
func NewTOTPEnrollmentPreparer(keys *keyring.Provider, key string) (*TOTPEnrollmentPreparer, error) {
	if keys == nil || len(key) == 0 || len(key) > 256 || strings.TrimSpace(key) != key || strings.ContainsAny(key, "\x00\r\n") {
		return nil, invalidAuthority()
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, invalidAuthority()
	}
	return &TOTPEnrollmentPreparer{crypto: crypto, key: strings.Clone(key)}, nil
}

// Prepare generates a 256-bit random factor and seals it under the existing
// totp-secret-v1 tenant/user/factor/enrollment/profile context. It returns no
// plaintext or provisioning URI. Restore original encrypted preparation on
// retries; calling Prepare again is new entropy, not idempotent generation.
// Earlier cancellation wins; crypto failures are redacted Unavailable errors.
func (p *TOTPEnrollmentPreparer) Prepare(ctx context.Context, r TOTPEnrollmentPreparation) (PreparedTOTPEnrollment, error) {
	if ctx == nil || p == nil || p.crypto == nil {
		return PreparedTOTPEnrollment{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return PreparedTOTPEnrollment{}, err
	}
	for _, id := range []string{string(r.TenantID), string(r.UserID)} {
		if _, err := identity.ParseIdentifierID(id); err != nil {
			return PreparedTOTPEnrollment{}, invalidAuthority()
		}
	}
	if _, err := identity.ParseCommandID(r.FactorID); err != nil {
		return PreparedTOTPEnrollment{}, invalidAuthority()
	}
	expires := r.CreatedAt.Add(r.TTL)
	if r.AuthorityVersion == 0 || r.AuthorityVersion == math.MaxUint64 || r.Profile.Validate() != nil || (r.Profile.Digits != 6 && r.Profile.Digits != 8) || r.CreatedAt.IsZero() || r.CreatedAt.Year() < 1 || r.CreatedAt.Year() > 9999 || r.CreatedAt.Nanosecond()%1000 != 0 || r.TTL < time.Second || r.TTL > 15*time.Minute || r.TTL%time.Microsecond != 0 || expires.Year() > 9999 {
		return PreparedTOTPEnrollment{}, invalidAuthority()
	}
	binding, err := totpEncryptionContext(r.TenantID, r.UserID, r.FactorID, 1, r.Profile)
	if err != nil {
		return PreparedTOTPEnrollment{}, err
	}
	secret := make([]byte, 32)
	defer clear(secret)
	if _, err = rand.Read(secret); err != nil {
		return PreparedTOTPEnrollment{}, identity.UnavailableError{}
	}
	sealed, err := p.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: secret, KeyReference: p.key, Context: binding})
	if cause := ctx.Err(); cause != nil {
		return PreparedTOTPEnrollment{}, cause
	}
	if err != nil {
		return PreparedTOTPEnrollment{}, identity.UnavailableError{}
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) == 0 || len(wire) > 4096 {
		clear(wire)
		return PreparedTOTPEnrollment{}, identity.UnavailableError{}
	}
	owned := preparedTOTPEnrollment{metadata: PendingTOTPMetadata{TenantID: r.TenantID, UserID: r.UserID, FactorID: r.FactorID, AuthorityVersion: r.AuthorityVersion, Profile: r.Profile, CreatedAt: r.CreatedAt.UTC(), ExpiresAt: expires.UTC()}, wire: slices.Clone(wire), binding: binding}
	clear(wire)
	if cause := ctx.Err(); cause != nil {
		clear(owned.wire)
		return PreparedTOTPEnrollment{}, cause
	}
	return PreparedTOTPEnrollment{custody: func() preparedTOTPEnrollment { return owned }}, nil
}

// Metadata returns owned scalar preparation data, never current authority.
func (p PreparedTOTPEnrollment) Metadata() (PendingTOTPMetadata, error) {
	if p.custody == nil {
		return PendingTOTPMetadata{}, invalidAuthority()
	}
	return p.custody().metadata, nil
}

// Envelope returns immutable encrypted custody without decrypting it.
func (p PreparedTOTPEnrollment) Envelope() (envelope.Envelope, error) {
	if p.custody == nil {
		return envelope.Envelope{}, invalidAuthority()
	}
	return envelope.ParseEnvelope(slices.Clone(p.custody().wire))
}

// EncryptionContext returns the original immutable authenticated context.
func (p PreparedTOTPEnrollment) EncryptionContext() (envelope.Context, error) {
	if p.custody == nil {
		return envelope.Context{}, invalidAuthority()
	}
	return p.custody().binding, nil
}

// Fields returns non-secret static intent fields. Generation instants and
// ciphertext are retained by encrypted preparation, not resampled retry input.
func (p PreparedTOTPEnrollment) Fields() ([]identity.FeatureField, error) {
	if p.custody == nil {
		return nil, invalidAuthority()
	}
	m := p.custody().metadata
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	number := func(name string, value uint64) identity.FeatureField {
		return identity.FeatureField{Name: name, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value}}
	}
	return []identity.FeatureField{text("factor.id", m.FactorID), text("factor.method", "totp"), text("factor.algorithm", m.Profile.Algorithm), text("factor.issuer", m.Profile.Issuer), number("factor.authority-version", m.AuthorityVersion), number("factor.digits", uint64(m.Profile.Digits)), number("factor.period-seconds", uint64(m.Profile.Period/time.Second)), number("factor.skew-steps", uint64(m.Profile.AllowedSkewSteps)), number("factor.enrollment-ttl-nanos", uint64(m.ExpiresAt.Sub(m.CreatedAt)))}, nil
}

// Persist creates one pending factor with primary-proof use and the existing
// command/audit/lifecycle owner in the same transaction. It never activates a
// factor or reveals a secret. Account-factor authority is locked before factor
// rows; unknown, stale or already-active state denies this first-factor profile.
// At most eight live pending enrollments are permitted per account. Creation
// advances the factor generation but keeps active_factors zero.
//
// The exact MFA participant must enforce policy/risk and browser CSRF/origin,
// restore original encrypted generation on retries, call Check after later
// waits and return every error to the coordinator. No transaction, callback
// registration, entropy, encryption or private journal is created here.
func (p PreparedTOTPEnrollment) Persist(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, primary TOTPEnrollmentPrimaryAdmission) error {
	if ctx == nil || p.custody == nil || primary == nil {
		return invalidAuthority()
	}
	v := reflect.ValueOf(primary)
	if (v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface) && v.IsNil() {
		return invalidAuthority()
	}
	if err := w.RequireFeatureCommand(ctx, owner, c); err != nil {
		return err
	}
	b, f, life, err := w.FeatureScope(owner)
	owned := p.custody()
	m := owned.metadata
	if err != nil || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) || f.Operation.Owner != "identity/mfa" || f.Operation.OperationID != "identity.mfa.enable" || f.Operation.SchemaID != "mfa-enable" || f.Operation.SchemaVersion != 1 || life.EventType != "factor.enrollment-created.v1" || life.BeforeVersion != 0 || life.AfterVersion != 1 || b.TenantID != m.TenantID || b.UserID != m.UserID || b.RecordID != m.FactorID {
		return invalidAuthority()
	}
	spec, ok := c.Feature()
	if !ok || spec.Binding != b {
		return invalidAuthority()
	}
	expected, err := p.Fields()
	if err != nil {
		return err
	}
	for _, field := range expected {
		found := false
		for _, got := range spec.Fields {
			if got.Name == field.Name && reflect.DeepEqual(got.Value, field.Value) {
				found = true
				break
			}
		}
		if !found {
			return identity.ForbiddenError{}
		}
	}
	if err = primary.Consume(ctx, w, owner, c); err != nil {
		return err
	}
	if _, err = readFactorAuthority(ctx, w, b, b.UserID, m.AuthorityVersion); err != nil {
		return err
	}
	rows, err := w.Query(ctx, `SELECT a.active_factors,(SELECT count(*) FROM identity_mfa.totp_factors t WHERE t.tenant_id=a.tenant_id AND t.user_id=a.user_id AND t.state=1 AND t.enrollment_expires_at>clock_timestamp()) FROM identity_mfa.factor_authorities a WHERE a.tenant_id=$1 AND a.user_id=$2`, string(b.TenantID), string(b.UserID))
	if err != nil {
		return err
	}
	var active int32
	var pending int64
	if !rows.Next() {
		rowErr := rows.Err()
		rows.Close()
		if rowErr != nil {
			return rowErr
		}
		return identity.ForbiddenError{}
	}
	err = rows.Scan(&active, &pending)
	extra := rows.Next()
	rowErr := rows.Err()
	rows.Close()
	if err != nil || extra || rowErr != nil {
		return identity.UnavailableError{}
	}
	if active != 0 || pending < 0 || pending >= 8 {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(m.CreatedAt) || !now.Before(m.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return invalidAuthority()
	}
	n, err := w.Exec(ctx, `INSERT INTO identity_mfa.totp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,encrypted_secret,created_command_id,created_purpose,created_at,enrollment_expires_at) VALUES($1,$2,$3,1,1,1,$4,$5,$6,$7,$8,$9,$10,'identity.mfa.enable',$11,$12)`, string(b.TenantID), string(b.UserID), m.FactorID, m.Profile.Algorithm, int16(m.Profile.Digits), int16(m.Profile.Period/time.Second), int16(m.Profile.AllowedSkewSteps), m.Profile.Issuer, owned.wire, id, m.CreatedAt, m.ExpiresAt)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	n, err = w.Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND version=$3::numeric AND active_factors=0`, string(b.TenantID), string(b.UserID), strconv.FormatUint(m.AuthorityVersion, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	if err = primary.Check(ctx, w, owner, c); err != nil {
		return err
	}
	now, err = w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if !now.Before(m.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}

// Recover reconciles only this exact original pending-factor creation. Combine
// it with primary-proof and required lifecycle recovery; it is not complete
// enrollment or current factor authority. No secret is returned or regenerated.
// Confirmed/revoked successors retain creation identity; terminal command
// receipts remain the historical authority after privacy/retention cleanup.
func (p PreparedTOTPEnrollment) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || p.custody == nil {
		return kernel.RecoveryUnknown, invalidAuthority()
	}
	b, f, life, err := w.FeatureScope(owner)
	m := p.custody().metadata
	if err != nil || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) || f.Operation.Owner != "identity/mfa" || f.Operation.OperationID != "identity.mfa.enable" || life.EventType != "factor.enrollment-created.v1" || life.BeforeVersion != 0 || life.AfterVersion != 1 || b.TenantID != m.TenantID || b.UserID != m.UserID || b.RecordID != m.FactorID {
		return kernel.RecoveryUnknown, invalidAuthority()
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, invalidAuthority()
	}
	rows, err := w.Query(ctx, `SELECT user_id,factor_id,algorithm,digits,period_seconds,skew_steps,issuer,created_at,enrollment_expires_at FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND created_purpose='identity.mfa.enable' AND created_command_id=$2`, string(b.TenantID), id)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var user, factor, algorithm, issuer string
	var digits, period, skew int16
	var created, expires time.Time
	if rows.Scan(&user, &factor, &algorithm, &digits, &period, &skew, &issuer, &created, &expires) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if user != string(m.UserID) || factor != m.FactorID || algorithm != m.Profile.Algorithm || int64(digits) != int64(m.Profile.Digits) || time.Duration(period)*time.Second != m.Profile.Period || int64(skew) != int64(m.Profile.AllowedSkewSteps) || issuer != m.Profile.Issuer || !created.Equal(m.CreatedAt) || !expires.Equal(m.ExpiresAt) {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	return kernel.RecoveryCommitted, nil
}

// Format redacts encrypted custody and identity metadata.
func (PreparedTOTPEnrollment) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.PreparedTOTPEnrollment(redacted)"))
}

// MarshalJSON denies implicit custody export.
func (PreparedTOTPEnrollment) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText denies implicit custody export.
func (PreparedTOTPEnrollment) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

// Format redacts local key/provider configuration.
func (TOTPEnrollmentPreparer) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.TOTPEnrollmentPreparer(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (TOTPEnrollmentPreparer) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText denies implicit configuration export.
func (TOTPEnrollmentPreparer) MarshalText() ([]byte, error) { return nil, invalidAuthority() }
