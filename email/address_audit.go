package email

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// AdministrativeReadAuditConfig selects mandatory primary audit acknowledgement
// for cross-subject/administrative address reads. Sink is an existing platform
// audit adapter, borrowed and concurrency-safe. MaximumDuration is positive and
// no greater than the query budget; earlier cancellation wins. There is no
// fail-open, detached recovery, retry journal or domain-store callback.
type AdministrativeReadAuditConfig struct {
	Sink            audit.Sink
	MaximumDuration time.Duration
}

type administrativeAddressAudit struct {
	builder         *audit.Builder
	recorder        *audit.Recorder
	maximumDuration time.Duration
}

// NewAuditedAddressQueryService preserves the ordinary query contract while
// explicitly enabling audited administrative access under the same authorizer.
// Selection is not permission. Successful and policy-denied administrative reads
// require a primary acknowledgement; any failure/unknown withholds projections.
// Records contain safe actor/tenant/policy, operation and authorized subject IDs,
// never address values, cursors, credentials or untrusted denied target IDs.
// Existing NewAddressQueryService remains self-only until this audit is selected.
func NewAuditedAddressQueryService(repo identity.IdentifierRepository, auth authorization.Service, redact identity.RedactFunc, config identity.UserQueryConfig, auditing AdministrativeReadAuditConfig) (*AddressQueryService, error) {
	s, err := NewAddressQueryService(repo, auth, redact, config)
	if err != nil {
		return nil, err
	}
	if nilAddressDependency(auditing.Sink) || auditing.MaximumDuration <= 0 || auditing.MaximumDuration > config.MaximumDuration {
		return nil, identity.InvalidInputError{Field: "email_query_audit"}
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{Clock: config.Clock.Now})
	if err != nil {
		return nil, identity.InvalidInputError{Field: "email_query_audit"}
	}
	redactor, err := audit.NewRedactor(audit.RedactionRules{DropDescription: true, DropNetworkOrigin: true, DropUserAgent: true, AllowedAttributes: []string{"retention.class", "identity.access"}})
	if err != nil {
		return nil, identity.InvalidInputError{Field: "email_query_audit"}
	}
	recorder, err := audit.NewRecorder(audit.RecorderConfig{Sink: auditing.Sink, Redactor: redactor, Mode: audit.DeliveryFailClosed})
	if err != nil {
		return nil, identity.InvalidInputError{Field: "email_query_audit"}
	}
	s.administrativeAudit = &administrativeAddressAudit{builder, recorder, auditing.MaximumDuration}
	return s, nil
}

// AdministrativeQueriesConfigured reports explicit required-audit composition,
// not caller permission, current identity authority or a freshness lease.
func (s *AddressQueryService) AdministrativeQueriesConfigured() bool {
	return s != nil && s.administrativeAudit != nil
}

func administrativeAddressTarget(target identity.UserID, caller authorization.DecisionContext) (identity.UserID, bool) {
	if target == "" {
		target = identity.UserID(caller.Request.Subject.ID)
	}
	return target, caller.Request.Subject.Kind != authorization.SubjectUser || target != identity.UserID(caller.Request.Subject.ID)
}

// AddressGet returns only authorized primary email metadata, acknowledging the
// required administrative audit before disclosure. Zero/nil and failures deny.
func (s *AddressQueryService) AddressGet(ctx context.Context, r AddressGetRequest) (out AddressGetResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = AddressGetResult{}, identity.UnavailableError{}
		}
	}()
	if s == nil || ctx == nil {
		return out, identity.InvalidInputError{Field: "email_query"}
	}
	bounded, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	out, err = s.addressGet(bounded, r)
	if e := s.finishAddressRead(bounded, r.TenantID, r.TargetSubjectID, r.Caller, "identity.email.address-get", err); e != nil {
		return AddressGetResult{}, e
	}
	if err != nil {
		return AddressGetResult{}, err
	}
	return out, nil
}

// AddressList preserves bounded actor/target-bound pagination and acknowledges
// required administrative audit before returning any page. Self reads do not
// create administrative records. Cancellation never launches background work.
func (s *AddressQueryService) AddressList(ctx context.Context, r AddressListRequest) (out AddressListResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = AddressListResult{}, identity.UnavailableError{}
		}
	}()
	if s == nil || ctx == nil {
		return out, identity.InvalidInputError{Field: "email_query"}
	}
	bounded, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer stop()
	out, err = s.addressList(bounded, r)
	if e := s.finishAddressRead(bounded, r.TenantID, r.TargetSubjectID, r.Caller, "identity.email.address-list", err); e != nil {
		return AddressListResult{}, e
	}
	if err != nil {
		return AddressListResult{}, err
	}
	return out, nil
}

func (s *AddressQueryService) finishAddressRead(ctx context.Context, tenant identity.TenantID, target identity.UserID, caller authorization.DecisionContext, action authorization.Action, readErr error) error {
	if e := addressContextError(ctx); e != nil {
		return e
	}
	target, administrative := administrativeAddressTarget(target, caller)
	if !administrative {
		return nil
	}
	if !s.AdministrativeQueriesConfigured() {
		if readErr != nil {
			return nil
		}
		return identity.UnavailableError{}
	}
	if !verificationID(string(target)) || caller.Request.Resource.ID != authorization.ResourceID(target) || caller.PolicyRevision != authorization.Revision(s.config.PolicyVersion) || validateEmailCaller(tenant, caller, action) != nil {
		return nil
	}
	outcome := audit.OutcomeSucceeded
	subject := string(target)
	if readErr != nil {
		subject = "undisclosed"
		outcome = audit.OutcomeFailed
		var denied identity.ForbiddenError
		if errors.As(readErr, &denied) {
			outcome = audit.OutcomeDenied
		}
	}
	kind := audit.ActorHuman
	if caller.Request.Subject.Kind != authorization.SubjectUser {
		kind = audit.ActorService
	}
	record, err := s.administrativeAudit.builder.Build(audit.RecordInput{OccurredAt: s.config.Clock.Now().UTC(), Action: string(action), Outcome: outcome, Actor: audit.ActorInput{Kind: kind, ID: string(caller.Request.Subject.ID)}, Subject: audit.SubjectInput{Type: "identity.user", ID: subject}, Context: audit.ContextInput{TenantID: string(tenant)}, Policy: audit.PolicyMetadata{PolicyID: s.config.PolicyID, Version: strconv.FormatUint(s.config.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{NoChange: true}, Attributes: map[string]string{"retention.class": "protected", "identity.access": "administrative"}})
	if err != nil {
		return identity.UnavailableError{}
	}
	bounded, stop := context.WithTimeout(ctx, s.administrativeAudit.maximumDuration)
	defer stop()
	result, err := s.administrativeAudit.recorder.Submit(bounded, record)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || bounded.Err() != nil || result.Disposition != audit.DeliveryPersisted {
		return identity.UnavailableError{}
	}
	return nil
}

// Format omits the borrowed sink and deployment policy.
func (AdministrativeReadAuditConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("email.AdministrativeReadAuditConfig(redacted)"))
}

// MarshalJSON denies implicit deployment-resource export.
func (AdministrativeReadAuditConfig) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
