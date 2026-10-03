package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// CommandAdmission is either an authorized primary absence observation or safe
// historical command metadata. The zero value is invalid. Absent does not
// prove noncommit of a previously submitted command, reserve the command ID,
// grant execution authority, or prevent a concurrent reservation after the read.
// Record exposes no native payload or private command fingerprint. Copies are
// safe for concurrent reading; Record.Feature is an owned mutable scalar copy.
type CommandAdmission struct {
	Absent bool
	Record CommandRecord
}

// Validate checks the exclusive observation shape, not authorization, primary
// provenance, intent equality or permission to evaluate providers. Native
// adapters must additionally match their retained pre-evaluation intent before
// replay; ReserveCommand remains the complete command-intent collision fence.
func (a CommandAdmission) Validate() error {
	if a.Absent && a.Record == (CommandRecord{}) || !a.Absent && a.Record.Validate() == nil {
		return nil
	}
	return identity.InvalidInputError{Field: "command_admission"}
}

// ObserveCommandAdmission performs one bounded current-policy decision and one
// uncached primary command-ID read for trusted native composition. Only an
// authorized actual missing global claim returns Absent. Denied callers never
// learn absence or history; retired or wrong-scope claims return Forbidden,
// incomplete/corrupt history and outages fail closed. Terminal history preserves
// QueryCommand's safe outcome and classified error; pending remains pending,
// including expired leases. No transaction, participant, reservation or lease is
// created, locked, renewed or changed.
//
// AdmissionPolicy is a separate opt-in from QueryPolicy. Its owned attributes
// set identity.command.read-admission=true and identity.command.recovery=false.
// The caller must be trusted authenticated composition bound to exact actor,
// tenant, operation and identity.user resource at the current configured policy
// revision, never a client-supplied override. This is not a public lookup route.
// Native adapters own further exact retained-intent matching and protected
// native-result recovery. Absence cannot substitute for ReserveCommand's atomic
// complete-intent fence or provide rollback proof after an ambiguous submission.
func (c *Coordinator) ObserveCommandAdmission(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (CommandAdmission, error) {
	if ctx == nil || c == nil || c.commandRead == nil || c.admissionPolicy == nil || c.maximumDuration <= 0 || c.maximumDuration > time.Minute {
		return CommandAdmission{}, coordinatorError()
	}
	if _, err := identity.ParseCommandID(string(q.CommandID)); err != nil {
		return CommandAdmission{}, identity.InvalidInputError{Field: "command_id"}
	}
	for _, value := range []string{string(q.TenantID), string(q.UserID), string(q.ActorID), string(q.ActorKind), q.OperationID} {
		if !queryScopeText(value) {
			return CommandAdmission{}, identity.InvalidInputError{Field: "command_query"}
		}
	}
	if q.RecordID != "" && !queryScopeText(q.RecordID) {
		return CommandAdmission{}, identity.InvalidInputError{Field: "command_query"}
	}
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return CommandAdmission{}, readFailure(bounded, err)
	}
	allowed, policyErr := authorizeCommandObservation(bounded, q, caller, c.admissionPolicy, true)
	// Preserve the policy/read shape even on valid denial. Unlike QueryCommand,
	// this explicitly authorized native boundary may disclose actual absence.
	observed, err := c.commandRead(bounded, q.CommandID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) || bounded.Err() != nil {
		return CommandAdmission{}, readFailure(bounded, err)
	}
	if policyErr != nil {
		return CommandAdmission{}, identity.UnavailableError{}
	}
	if !allowed {
		return CommandAdmission{}, identity.ForbiddenError{}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return CommandAdmission{Absent: true}, nil
	}
	receipt, err := commandReceipt(q, observed, nil)
	if receipt.Outcome == identity.CommitOutcomeInvalid {
		return CommandAdmission{}, err
	}
	return CommandAdmission{Record: commandRecord(receipt)}, err
}
