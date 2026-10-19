package passwordpostgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// Restore only the original committed encrypted request and generation. Neither
// an expired sending proof nor expired sending-risk evidence is renewed here;
// Update separately admits a distinct fresh proof before any code is compared.
func (s *phoneChangeService) restoreChangeSource(ctx context.Context, tenant identity.TenantID, user identity.UserID, caller authorization.DecisionContext, flow otp.SendFlow, send identity.CommandID, csrf session.CSRFToken) (*phoneChangeSendPhase, otppg.PhoneChangeConfirmation, error) {
	bad := func(err error) (*phoneChangeSendPhase, otppg.PhoneChangeConfirmation, error) {
		return nil, otppg.PhoneChangeConfirmation{}, err
	}
	_, sessionID, bearer, err := flow.Bindings()
	if err != nil {
		return bad(password.ErrPasswordWork)
	}
	actual, err := s.common.possessedPhoneSession(ctx, tenant, flow)
	if err != nil {
		return bad(err)
	}
	current, err := actual.Bindings()
	if err != nil || current.UserID != user || s.common.checkCSRF(actual, csrf) != nil {
		return bad(identity.ForbiddenError{})
	}
	p := &phoneChangeSendPhase{service: s}
	p.request.Enrollment.UserID, p.request.Enrollment.Session = user, bearer
	p.request.Enrollment.Caller, p.request.Enrollment.CSRFToken = caller, csrf
	coordinator, _, err := s.coordinator(p, nil)
	if err != nil {
		return bad(err)
	}
	q := identity.RecoveryQuery{TenantID: tenant, UserID: user, CommandID: send, RecordID: string(send), ActorKind: authorization.SubjectUser, ActorID: identity.ActorID(user), OperationID: phoneChangeSendingOperation().OperationID}
	record, err := coordinator.QueryPreparedFeature(ctx, q, s.common.phoneQueryCaller(caller, q, true), kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: phoneChangeSendingOperation()}, p)
	if err != nil {
		return bad(err)
	}
	defer clear(record.InputCiphertext)
	defer clear(record.OutputCiphertext)
	if err = p.restoreStoredRequest(ctx, record.InputBinding, record.InputCiphertext, false); err != nil {
		return bad(err)
	}
	original, err := p.primary.Original()
	if err != nil {
		return bad(err)
	}
	b, err := original.Bindings()
	if err != nil || b.TenantID != tenant || b.UserID != user || b.SessionID != sessionID {
		return bad(identity.ForbiddenError{})
	}
	aad, err := p.outputAAD(record.OutputGeneration)
	if err != nil {
		return bad(err)
	}
	plain, err := s.common.openPhone(ctx, record.OutputCiphertext, aad)
	if err != nil {
		return bad(err)
	}
	defer clear(plain)
	var stored phoneEnrollmentOutput
	if decodeKeyedPasswordJSON(plain, &stored) != nil || stored.Schema != 1 || len(stored.OTP) == 0 || len(stored.OTP) > maximumKeyedPasswordCustody {
		return bad(password.ErrPasswordWork)
	}
	defer clear(stored.OTP)
	confirmation, err := s.config().Issuer.RestoreChangeConfirmation(ctx, p.command, p.input, record.OutputGeneration, stored.OTP)
	if err != nil {
		return bad(err)
	}
	return p, confirmation, nil
}
