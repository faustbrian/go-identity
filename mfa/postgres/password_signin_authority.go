package mfapostgres

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// ReadPasswordSigninFactors selects known primary factor state after password
// comparison. It grants no authentication or freshness lease; the native owner
// must fence the returned generation in its protected Work. Missing state denies
// rather than implying no MFA. The pool is borrowed and the read is bounded.
func ReadPasswordSigninFactors(ctx context.Context, pool *database.Pool, tenant identity.TenantID, user identity.UserID, maximum time.Duration) (uint64, bool, error) {
	if ctx == nil || pool == nil || pool.Raw() == nil || maximum <= 0 || maximum > 5*time.Second {
		return 0, false, invalidAuthority()
	}
	if _, err := identity.ParseIdentifierID(string(tenant)); err != nil {
		return 0, false, invalidAuthority()
	}
	if _, err := identity.ParseIdentifierID(string(user)); err != nil {
		return 0, false, invalidAuthority()
	}
	bounded, stop := context.WithTimeout(ctx, maximum)
	defer stop()
	var version string
	var active int32
	if err := pool.Raw().QueryRow(bounded, `SELECT version::text,active_factors FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, string(tenant), string(user)).Scan(&version, &active); err != nil {
		if bounded.Err() != nil {
			return 0, false, bounded.Err()
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, identity.ForbiddenError{}
		}
		return 0, false, identity.UnavailableError{}
	}
	v, err := strconv.ParseUint(version, 10, 64)
	if err != nil || active < 0 {
		return 0, false, identity.UnavailableError{}
	}
	if _, err := mfa.NewFactorAuthority(mfa.AuthorityRecord{TenantID: tenant, UserID: user, Version: v, ActiveFactors: uint32(active)}); err != nil {
		return 0, false, invalidAuthority()
	}
	return v, active > 0, bounded.Err()
}

// RequirePasswordSigninFactors locks the exact current generation through the
// sole password transaction. A challenge requires its closed native owner and a
// confirmed TOTP method; SFA requires known empty state. No secret or session is
// returned and every error must abort Work. Original expectedVersion is never
// replaced by the latest generation. Both Apply and final commit checks may use
// this guard; it creates no transaction, callback, enrollment or factor attempt.
func RequirePasswordSigninFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, user identity.UserID, version uint64, challenge bool) error {
	return requirePasswordSigninFactors(ctx, w, owner, command, user, version, challenge, []string{"totp"})
}

// RequirePasswordSigninFactorMethods fences explicit password-first TOTP/OTP
// selection in the native challenge transaction. Supply the unchanged methods
// from the authenticated original continuation, not request-selected strings.
// At least one selected primary factor must be confirmed; recovery alone is not
// enrollment. OTP additionally requires its owned verified identifier at exact
// retained versions/channel. Missing selected storage denies. Neither verified
// email nor an unrelated enrolled method authorizes a challenge. The borrowed
// slice must not be mutated during this call. No method, proof or session is
// issued here; completion repeats its own current authority and budget fences.
func RequirePasswordSigninFactorMethods(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, user identity.UserID, version uint64, methods []string) error {
	if len(methods) == 0 || len(methods) > 3 {
		return invalidAuthority()
	}
	for i, method := range methods {
		if method != "totp" && method != "otp" && method != "recovery-code" || slices.Contains(methods[:i], method) {
			return invalidAuthority()
		}
	}
	if !slices.Contains(methods, "totp") && !slices.Contains(methods, "otp") {
		return invalidAuthority()
	}
	return requirePasswordSigninFactors(ctx, w, owner, command, user, version, true, methods)
}

func requirePasswordSigninFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, user identity.UserID, version uint64, challenge bool, methods []string) error {
	if ctx == nil || owner == nil || version == 0 {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s, ok := command.PasswordSigninFeature()
	b, f, life, err := w.FeatureScope(owner)
	username := f.Operation.Owner == "identity/username" && b.OperationID == "identity.username.signin" && f.Operation.SchemaID == "username-signin"
	phone := f.Operation.Owner == "identity/phone" && b.OperationID == "identity.phone.password-signin" && f.Operation.SchemaID == "phone-password-signin"
	profile := f.Operation.Owner == "identity/password" && b.OperationID == "identity.password.signin" && f.Operation.SchemaID == "password-signin" || username || phone
	// Username and verified-phone comparisons retain distinct original
	// challenges, but both select only the independently enrolled TOTP owner.
	// Neither profile may reinterpret the phone/SMS itself as a second factor.
	if (username || phone) && challenge && (len(methods) != 1 || methods[0] != "totp") {
		return invalidAuthority()
	}
	if err != nil || !ok || !profile || f.Operation.SchemaVersion != 1 || f.Operation.RecordRequirement != identity.FeatureRecordOmitted || f.Operation.SubjectRequirement > identity.FeatureSubjectAnonymousFlow || b.ValidateFor(f.Operation) != nil || s.Binding != b || s.Operation != f.Operation || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) {
		return invalidAuthority()
	}
	if challenge {
		if _, ok := owner.(kernel.PasswordMFAChallengeContributor); !ok || life.EventType != "mfa.challenge.created.v1" {
			return invalidAuthority()
		}
	} else if life.EventType != "session.created.v1" {
		return invalidAuthority()
	}
	state, err := readFactorAuthority(ctx, w, b, user, version)
	if err != nil {
		return err
	}
	if !challenge {
		return state.RequireEmailRecovery(b.TenantID, user)
	}
	if state.RequireEmailRecovery(b.TenantID, user) == nil {
		return identity.ForbiddenError{}
	}
	found := false
	for _, method := range []string{"totp", "otp"} {
		if !slices.Contains(methods, method) {
			continue
		}
		query := `SELECT factor_id FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND state=2 AND confirmed_at IS NOT NULL AND encrypted_secret IS NOT NULL LIMIT 1`
		if method == "otp" {
			query = `SELECT f.factor_id FROM identity_mfa.otp_factors f
JOIN identity.identifiers i ON i.tenant_id=f.tenant_id AND i.user_id=f.user_id AND i.identifier_id=f.identifier_id
WHERE f.tenant_id=$1 AND f.user_id=$2 AND f.state=2 AND f.confirmed_at IS NOT NULL
AND i.verified AND i.verification_state=2 AND i.verified_at IS NOT NULL
AND i.version=f.identifier_version AND i.verification_version=f.verification_version
AND ((f.channel='email' AND i.kind='email') OR (f.channel='sms' AND i.kind='phone'))
LIMIT 1 FOR SHARE OF f,i`
		}
		present, err := passwordSigninFactorPresent(ctx, w, query, b.TenantID, user)
		if err != nil {
			return err
		}
		found = found || present
	}
	if !found {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func passwordSigninFactorPresent(ctx context.Context, w kernel.Work, query string, tenant identity.TenantID, user identity.UserID) (bool, error) {
	rows, err := w.Query(ctx, query, string(tenant), string(user))
	if err != nil {
		return false, identity.UnavailableError{}
	}
	defer rows.Close()
	var id string
	if !rows.Next() {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if rows.Err() != nil {
			return false, identity.UnavailableError{}
		}
		return false, nil
	}
	if rows.Scan(&id) != nil || rows.Next() || rows.Err() != nil {
		return false, identity.UnavailableError{}
	}
	if _, err := identity.ParseCommandID(id); err != nil {
		return false, identity.ForbiddenError{}
	}
	return true, ctx.Err()
}
