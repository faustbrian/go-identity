package mfapostgres

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// PendingOTPMetadata is the exact original code-free enrollment projection.
// Identifier/version fields must come from native verified-recipient admission,
// not from treating a client selection as authority. AuthorityVersion is fenced
// in the owning transaction; timestamps retain the original database lifetime.
// Construction alone proves neither persistence, enrollment nor authentication.
type PendingOTPMetadata struct {
	TenantID                                                 identity.TenantID
	UserID                                                   identity.UserID
	FactorID                                                 string
	IdentifierID                                             identity.IdentifierID
	Channel                                                  delivery.Channel
	AuthorityVersion, IdentifierVersion, VerificationVersion uint64
	CreatedAt, ExpiresAt                                     time.Time
}

// PreparedOTPEnrollment retains immutable original metadata, not a generated
// OTP or a successful factor proof. Codes/digests/delivery stay with OTP's real
// owners. Copies are safe for concurrent reads; projections cannot mutate them.
type PreparedOTPEnrollment struct{ state *PendingOTPMetadata }

// NewPreparedOTPEnrollment validates bounded metadata without IO, entropy,
// hashing, policy inference or clock reads. Native admission must authenticate
// and fence its origin/current state before any protected persistence. Zero
// versions, unadvanceable authority and non-microsecond/invalid lifetimes deny.
func NewPreparedOTPEnrollment(m PendingOTPMetadata) (PreparedOTPEnrollment, error) {
	for _, id := range []string{string(m.TenantID), string(m.UserID), string(m.IdentifierID)} {
		if _, err := identity.ParseIdentifierID(id); err != nil {
			return PreparedOTPEnrollment{}, invalidAuthority()
		}
	}
	if _, err := identity.ParseCommandID(m.FactorID); err != nil {
		return PreparedOTPEnrollment{}, invalidAuthority()
	}
	if m.AuthorityVersion == 0 || m.AuthorityVersion == math.MaxUint64 || m.IdentifierVersion == 0 || m.VerificationVersion == 0 ||
		(m.Channel != delivery.ChannelEmail && m.Channel != delivery.ChannelSMS) ||
		m.CreatedAt.IsZero() || m.CreatedAt.Year() < 1 || m.CreatedAt.Year() > 9999 || m.CreatedAt.Nanosecond()%1000 != 0 ||
		m.ExpiresAt.IsZero() || m.ExpiresAt.Year() > 9999 || m.ExpiresAt.Nanosecond()%1000 != 0 ||
		!m.ExpiresAt.After(m.CreatedAt) || m.ExpiresAt.Sub(m.CreatedAt) < time.Second || m.ExpiresAt.Sub(m.CreatedAt) > 15*time.Minute {
		return PreparedOTPEnrollment{}, invalidAuthority()
	}
	m.TenantID = identity.TenantID(strings.Clone(string(m.TenantID)))
	m.UserID = identity.UserID(strings.Clone(string(m.UserID)))
	m.IdentifierID = identity.IdentifierID(strings.Clone(string(m.IdentifierID)))
	m.FactorID = strings.Clone(m.FactorID)
	m.CreatedAt, m.ExpiresAt = m.CreatedAt.UTC().Round(0), m.ExpiresAt.UTC().Round(0)
	return PreparedOTPEnrollment{state: &m}, nil
}

// Metadata returns caller-owned original metadata, not current admission.
func (p PreparedOTPEnrollment) Metadata() (PendingOTPMetadata, error) {
	if p.state == nil {
		return PendingOTPMetadata{}, invalidAuthority()
	}
	return *p.state, nil
}

// Fields returns owned static command intent with exact recipient/channel and
// version bindings. No destination, code, bearer or caller-selected authority
// success flag is encoded; native original custody and primary admission remain
// required. Changing these fields cannot authorize changing the preparation.
func (p PreparedOTPEnrollment) Fields() ([]identity.FeatureField, error) {
	m, err := p.Metadata()
	if err != nil {
		return nil, err
	}
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	number := func(name string, value uint64) identity.FeatureField {
		return identity.FeatureField{Name: name, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value}}
	}
	channel := "email"
	if m.Channel == delivery.ChannelSMS {
		channel = "sms"
	}
	return []identity.FeatureField{text("factor.id", m.FactorID), text("factor.method", "otp"), text("factor.channel", channel),
		text("factor.identifier-id", string(m.IdentifierID)), number("factor.authority-version", m.AuthorityVersion),
		number("factor.identifier-version", m.IdentifierVersion), number("factor.verification-version", m.VerificationVersion),
		number("factor.enrollment-ttl-nanos", uint64(m.ExpiresAt.Sub(m.CreatedAt)))}, nil
}

// Persist consumes the original native primary and stores a pending OTP factor
// in the sole coordinator Work. It locks account factor authority before the
// exact verified recipient and method rows, fences original versions/lifetime,
// limits total live TOTP/OTP pending ceremonies to eight, and advances authority
// without activating a factor. It generates no code, secret or delivery and
// opens no transaction. Native risk/CSRF and recovery persistence remain the
// registered enrollment participant's responsibility; return every error.
func (p PreparedOTPEnrollment) Persist(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, primary TOTPEnrollmentPrimaryAdmission) error {
	if ctx == nil || p.state == nil || nilEnrollmentPrimary(primary) {
		return invalidAuthority()
	}
	if err := w.RequireFeatureCommand(ctx, owner, c); err != nil {
		return err
	}
	b, f, life, err := w.FeatureScope(owner)
	m := *p.state
	if err != nil || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) || f.Operation != enrollmentOperation() || life.EventType != "factor.enrollment-created.v1" || life.BeforeVersion != 0 || life.AfterVersion != 1 || b.TenantID != m.TenantID || b.UserID != m.UserID || b.RecordID != m.FactorID {
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
	authority, err := readFactorAuthority(ctx, w, b, b.UserID, m.AuthorityVersion)
	if err != nil {
		return err
	}
	if err := authority.RequireEmailRecovery(b.TenantID, b.UserID); err != nil {
		return err
	}
	if err := p.checkRecipient(ctx, w); err != nil {
		return err
	}
	rows, err := w.Query(ctx, `SELECT
(SELECT count(*) FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND state=1 AND enrollment_expires_at>clock_timestamp())+
(SELECT count(*) FROM identity_mfa.otp_factors WHERE tenant_id=$1 AND user_id=$2 AND state=1 AND enrollment_expires_at>clock_timestamp())`, string(m.TenantID), string(m.UserID))
	if err != nil {
		return err
	}
	var pending int64
	if !rows.Next() || rows.Scan(&pending) != nil || rows.Next() || rows.Err() != nil {
		rows.Close()
		return identity.UnavailableError{}
	}
	rows.Close()
	if pending < 0 || pending >= 8 {
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
	if err != nil || len(id) != 16 {
		return invalidAuthority()
	}
	channel := "email"
	if m.Channel == delivery.ChannelSMS {
		channel = "sms"
	}
	n, err := w.Exec(ctx, `INSERT INTO identity_mfa.otp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,channel,identifier_id,identifier_version,verification_version,created_command_id,created_purpose,created_at,enrollment_expires_at)
VALUES($1,$2,$3,1,1,1,$4,$5,$6::numeric,$7::numeric,$8,'identity.mfa.enable',$9,$10)`, string(m.TenantID), string(m.UserID), m.FactorID, channel, string(m.IdentifierID), strconv.FormatUint(m.IdentifierVersion, 10), strconv.FormatUint(m.VerificationVersion, 10), id, m.CreatedAt, m.ExpiresAt)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	n, err = w.Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND version=$3::numeric AND active_factors=0`, string(m.TenantID), string(m.UserID), strconv.FormatUint(m.AuthorityVersion, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	if err := primary.Check(ctx, w, owner, c); err != nil {
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

// The identifier is locked for the Work, so later waits cannot silently replace
// or revoke the selected recipient. No destination is projected or logged.
func (p PreparedOTPEnrollment) checkRecipient(ctx context.Context, w kernel.Work) error {
	if p.state == nil {
		return invalidAuthority()
	}
	m := *p.state
	rows, err := w.Query(ctx, `SELECT kind,verified,verification_state,version::text,verification_version::text,verified_at FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 FOR UPDATE`, string(m.TenantID), string(m.UserID), string(m.IdentifierID))
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return identity.ForbiddenError{}
	}
	var kind, version, verification string
	var verified bool
	var state int16
	var at *time.Time
	if rows.Scan(&kind, &verified, &state, &version, &verification, &at) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	if !verified || state != int16(identity.VerificationVerified) || at == nil || at.After(m.CreatedAt) || version != strconv.FormatUint(m.IdentifierVersion, 10) || verification != strconv.FormatUint(m.VerificationVersion, 10) || m.Channel == delivery.ChannelEmail && kind != "email" || m.Channel == delivery.ChannelSMS && kind != "phone" {
		return identity.ForbiddenError{}
	}
	return nil
}

// Format redacts original factor and identifier metadata.
func (PreparedOTPEnrollment) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.PreparedOTPEnrollment(redacted)"))
}

// MarshalJSON denies implicit original-metadata export.
func (PreparedOTPEnrollment) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText denies implicit textual metadata export.
func (PreparedOTPEnrollment) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

// LogValue redacts pending-enrollment metadata in structured logs.
func (PreparedOTPEnrollment) LogValue() slog.Value {
	return slog.StringValue("mfapostgres.PreparedOTPEnrollment(redacted)")
}
