package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// PreAuthWriter borrows bounded query/write operations from the original sole
// coordinator transaction. Exec returns affected rows, never a transaction or
// commit operation. The owner must fence scope/lifetime and abort/poison on
// every error. Autocommit pools, replicas and independently begun transactions
// are forbidden in production composition; this interface does not prove that
// ownership and must never be supplied from client input.
type PreAuthWriter[R SessionRows] interface {
	SessionQueryer[R]
	Exec(context.Context, string, ...any) (int64, error)
}

// PreAuthUse binds one pre-auth reservation to the exact frozen authenticated
// command, complete coordinator fingerprint and positive ownership generation.
// Values are structural correlation, not authentication or journal authority.
// The owning native participant derives them from its live sealed Work; never
// accept them from requests. Policy, tenant and action must match original flow.
type PreAuthUse struct {
	Command     identity.CommandBinding
	Fingerprint [32]byte
	Generation  uint64
}

// Format hides correlated custody.
func (PreAuthUse) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PreAuthUse(redacted)"))
}

// MarshalJSON rejects implicit custody disclosure.
func (PreAuthUse) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRecord }

// MarshalText rejects implicit custody disclosure.
func (PreAuthUse) MarshalText() ([]byte, error) { return nil, ErrInvalidRecord }

func (u PreAuthUse) valid(s session.PreAuthTransactionSpec) bool {
	_, err := identity.ParseCommandID(string(u.Command.CommandID))
	i := s.Binding.Intent
	return err == nil && u.Fingerprint != ([32]byte{}) && u.Generation > 0 && u.Command.TenantID == i.TenantID && u.Command.OperationID == i.Action && u.Command.PolicyID == i.PolicyID && u.Command.PolicyVersion == i.PolicyVersion
}

func preAuthContext(ctx context.Context, q any, c Config, record session.PreAuthTransaction) (context.Context, context.CancelFunc, session.PreAuthTransactionSpec, []byte, error) {
	invalid := func() (context.Context, context.CancelFunc, session.PreAuthTransactionSpec, []byte, error) {
		return nil, nil, session.PreAuthTransactionSpec{}, nil, identity.InvalidInputError{Field: "session_preauth"}
	}
	if ctx == nil || nilSessionHandle(q) || !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute {
		return invalid()
	}
	s, err := record.Bindings()
	if err != nil || s.Version > ^uint64(0)-2 {
		return invalid()
	}
	canonical, err := encodePreAuth(record)
	if err != nil {
		return invalid()
	}
	bounded, stop := context.WithTimeout(ctx, c.MaximumDuration)
	if bounded.Err() != nil {
		err = readError(bounded, bounded.Err())
		stop()
		return nil, nil, session.PreAuthTransactionSpec{}, nil, err
	}
	return bounded, stop, s, canonical, nil
}

// InsertPreAuth stages the original issued record inside the owned initiation
// command. It never reveals a cookie, samples/renews timestamps, closes the
// transaction or writes a command journal. Duplicate IDs/digests deny; they
// cannot overwrite or resurrect terminal flows. The issuance owner must recover
// ambiguous insertion by the existing command, not call this to mint another
// record. Public initiation/receipt recovery wiring is still separate work.
func InsertPreAuth[R SessionRows](ctx context.Context, q PreAuthWriter[R], c Config, record session.PreAuthTransaction) error {
	bounded, stop, s, canonical, err := preAuthContext(ctx, q, c, record)
	if err != nil {
		return err
	}
	defer stop()
	if s.Version != 1 {
		return identity.InvalidInputError{Field: "session_preauth"}
	}
	b := s.Binding
	count, err := q.Exec(bounded, `INSERT INTO `+pgx.Identifier{c.Schema}.Sanitize()+`.preauth_transactions(tenant_id,flow_id,record,issued_at,expires_at,digest_version,digest,issued_version,version,state)
 VALUES($1,$2,$3,$4,$5,$6,$7,1,1,'issued') ON CONFLICT DO NOTHING`, string(b.Intent.TenantID), string(b.ID), canonical, b.IssuedAt.Format(storedTimeLayout), b.ExpiresAt.Format(storedTimeLayout), int64(s.Cookie.KeyVersion), s.Cookie.Sum[:])
	return preAuthWriteResult(bounded, count, err)
}

// RequirePreAuth locks and admits only the exact original issued primary flow.
// It checks all binding fields, original version/cookie and database time AFTER
// lock acquisition. Success is not authentication or one-use consumption.
// Current access policy and credential owners remain the consuming workflow's
// checks. It retains no handle/cursor and performs no independent IO or write.
func RequirePreAuth[R SessionRows](ctx context.Context, q SessionQueryer[R], c Config, record session.PreAuthTransaction) error {
	bounded, stop, s, canonical, err := preAuthContext(ctx, q, c, record)
	if err != nil {
		return err
	}
	defer stop()
	return lockPreAuth(bounded, q, c, record, s, canonical, nil, false)
}

// ReservePreAuth changes issued to reserved exactly once under an update lock,
// binding the frozen command/fingerprint/generation. It does not authenticate
// or consume the flow. Commit/recovery is the existing coordinator's owner;
// expiration, retries and connection loss never release or renew a reservation.
func ReservePreAuth[R SessionRows](ctx context.Context, q PreAuthWriter[R], c Config, record session.PreAuthTransaction, use PreAuthUse) error {
	return transitionPreAuth(ctx, q, c, record, use, false)
}

// FinalizePreAuth consumes only the exact reserved owner, after locked primary
// time and complete original binding checks. Invoke in the same transaction as
// protected session/link effects. An error must abort the entire transaction.
// Terminal replay denies, even with the same command; the coordinator returns
// its original historical receipt instead of reexecuting this transition.
func FinalizePreAuth[R SessionRows](ctx context.Context, q PreAuthWriter[R], c Config, record session.PreAuthTransaction, use PreAuthUse) error {
	return transitionPreAuth(ctx, q, c, record, use, true)
}

func transitionPreAuth[R SessionRows](ctx context.Context, q PreAuthWriter[R], c Config, record session.PreAuthTransaction, use PreAuthUse, final bool) error {
	bounded, stop, s, canonical, err := preAuthContext(ctx, q, c, record)
	if err != nil {
		return err
	}
	defer stop()
	if !use.valid(s) {
		return identity.InvalidInputError{Field: "session_preauth_use"}
	}
	var custody *PreAuthUse
	if final {
		custody = &use
	}
	if err = lockPreAuth(bounded, q, c, record, s, canonical, custody, true); err != nil {
		return err
	}
	command, _ := base64.RawURLEncoding.DecodeString(string(use.Command.CommandID))
	state, successor := "reserved", s.Version+1
	if final {
		state, successor = "consumed", s.Version+2
	}
	count, err := q.Exec(bounded, `UPDATE `+pgx.Identifier{c.Schema}.Sanitize()+`.preauth_transactions SET state=$3,version=$4::numeric,command_id=$5,fingerprint=$6,generation=$7::numeric
 WHERE tenant_id=$1 AND flow_id=$2`, string(s.Binding.Intent.TenantID), string(s.Binding.ID), state, strconv.FormatUint(successor, 10), command, use.Fingerprint[:], strconv.FormatUint(use.Generation, 10))
	return preAuthWriteResult(bounded, count, err)
}

func preAuthWriteResult(ctx context.Context, count int64, err error) error {
	if err != nil || ctx.Err() != nil {
		return readError(ctx, err)
	}
	if count != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

func lockPreAuth[R SessionRows](ctx context.Context, q SessionQueryer[R], c Config, record session.PreAuthTransaction, s session.PreAuthTransactionSpec, canonical []byte, use *PreAuthUse, update bool) error {
	if err := lockPreAuthRecord(ctx, q, c, s, canonical, use, update); err != nil {
		return err
	}
	clockRows, err := q.Query(ctx, `SELECT clock_timestamp()`)
	if err != nil {
		return readError(ctx, err)
	}
	if nilSessionHandle(clockRows) {
		return identity.UnavailableError{}
	}
	var now time.Time
	err = readSessionAdmission(clockRows, &now)
	clockRows.Close()
	if err != nil {
		return admissionError(ctx, err)
	}
	if ctx.Err() != nil {
		return readError(ctx, ctx.Err())
	}
	if record.Check(now, s.Binding, s.Cookie) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

// Original record exclusion is shared by live admission and proven-noncommit
// release. Only live admission checks expiry: expiry cannot strand an owner
// after its protected transaction is authoritatively proven not to have committed.
func lockPreAuthRecord[R SessionRows](ctx context.Context, q SessionQueryer[R], c Config, s session.PreAuthTransactionSpec, canonical []byte, use *PreAuthUse, update bool) error {
	state, version, lock := "issued", s.Version, "SHARE"
	if use != nil {
		state, version = "reserved", s.Version+1
	}
	if update {
		lock = "UPDATE"
	}
	args := []any{string(s.Binding.Intent.TenantID), string(s.Binding.ID), state, strconv.FormatUint(version, 10), strconv.FormatUint(s.Version, 10), s.Binding.IssuedAt.Format(storedTimeLayout), s.Binding.ExpiresAt.Format(storedTimeLayout), int64(s.Cookie.KeyVersion), s.Cookie.Sum[:]}
	sql := `SELECT record FROM ` + pgx.Identifier{c.Schema}.Sanitize() + `.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2 AND state=$3 AND version=$4::numeric AND issued_version=$5::numeric AND issued_at=$6 AND expires_at=$7 AND digest_version=$8 AND digest=$9`
	if use != nil {
		command, _ := base64.RawURLEncoding.DecodeString(string(use.Command.CommandID))
		sql += ` AND command_id=$10 AND fingerprint=$11 AND generation=$12::numeric`
		args = append(args, command, use.Fingerprint[:], strconv.FormatUint(use.Generation, 10))
	}
	rows, err := q.Query(ctx, sql+` FOR `+lock, args...)
	if err != nil {
		return readError(ctx, err)
	}
	if nilSessionHandle(rows) {
		return identity.UnavailableError{}
	}
	var payload []byte
	err = readSessionAdmission(rows, &payload)
	rows.Close()
	if err != nil {
		return admissionError(ctx, err)
	}
	if _, err = decodePreAuth(payload); err != nil {
		return identity.UnavailableError{}
	}
	if !bytes.Equal(canonical, payload) {
		return identity.ForbiddenError{}
	}
	if ctx.Err() != nil {
		return readError(ctx, ctx.Err())
	}
	return nil
}
