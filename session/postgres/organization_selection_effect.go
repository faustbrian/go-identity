package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func organizationSelectionOwner() kernel.ContributorDescriptor {
	// This is go-organization/postgres.Contributor's existing membership
	// contract, not a new selection-only participant or registry exception.
	return kernel.ContributorDescriptor{Owner: "organization/postgres", ContractID: "organization.membership", Version: 1}
}

// OrganizationSelectionEffect owns the exact session CAS inside the logical
// organization participant's sole coordinator Work. It never opens a transaction
// or grants membership/permission. The organization owner must authenticate the
// original bearer, require target membership/policy and protected audit/outbox,
// and invoke Lock before acquiring its organization/member mutation locks.
// Immutable configuration permits independent concurrent calls; no goroutines
// or resources are owned. Install OrganizationSelectionMigrationSource first.
type OrganizationSelectionEffect struct {
	native  Repository
	config  Config
	profile OrganizationPasswordSessionAdmission
}

// NewOrganizationSelectionEffect freezes a single-factor password/bearer
// profile without IO. The borrowed organization authority must use the same
// primary database. Cookie/MFA/passkey variants remain disabled rather than
// silently losing provenance or browser protection. Zero/invalid input denies.
func NewOrganizationSelectionEffect(c Config, p OrganizationPasswordSessionAdmission) (*OrganizationSelectionEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !p.valid() {
		return nil, session.ErrInvalidSessionCommand
	}
	c.Schema = strings.Clone(c.Schema)
	return &OrganizationSelectionEffect{native: Repository{schema: `"` + c.Schema + `"`, maximumDuration: c.MaximumDuration}, config: c, profile: p}, nil
}

func (e *OrganizationSelectionEffect) intent(w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) (session.OrganizationSelectionCommandSpec, time.Time, kernel.LifecyclePlan, error) {
	deny := func() (session.OrganizationSelectionCommandSpec, time.Time, kernel.LifecyclePlan, error) {
		return session.OrganizationSelectionCommandSpec{}, time.Time{}, kernel.LifecyclePlan{}, session.ErrInvalidSessionCommand
	}
	if e == nil || owner == nil {
		return deny()
	}
	b, f, l, err := w.FeatureScope(owner)
	feature, ok := command.Feature()
	if err != nil || !ok || feature.Binding != b || f.Contributor != organizationSelectionOwner() || owner.Descriptor() != organizationSelectionOwner() || f.Operation != session.OrganizationSelectionOperation() || l.EventType != "session.organization_changed.v1" {
		return deny()
	}
	mapped, until, err := OrganizationSelectionFromFields(b, feature.Fields)
	if err != nil {
		return deny()
	}
	c, _ := mapped.Bindings()
	s, _ := c.Source.Bindings()
	n, _ := c.Successor.Bindings()
	if l.BeforeVersion != s.Version || l.AfterVersion != n.Version {
		return deny()
	}
	if _, _, _, err := OriginalOrganizationPasswordSessionAdmission(e.profile.Profile, c.Source, b); err != nil {
		return deny()
	}
	// The core transition clears version-bound CSRF. This native first profile
	// cannot deliver its replacement, so cookie records cannot enter it.
	if _, err := c.Source.CSRFState().Bindings(); err == nil {
		return deny()
	}
	return c, until, l, nil
}

func (e *OrganizationSelectionEffect) requirePrimary(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, b identity.CommandBinding, original session.Session) error {
	d, c, p, err := OriginalOrganizationPasswordSessionAdmission(e.profile.Profile, original, b)
	if err != nil {
		return err
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, d); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(ctx, owner, c); err != nil {
		return err
	}
	return w.RequireActiveUserAuthorization(ctx, owner, p)
}

func requireOriginalOrganization(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, p OrganizationPasswordSessionAdmission, original session.Session) error {
	s, err := original.Bindings()
	if err != nil {
		return session.ErrInvalidSessionCommand
	}
	v, _ := s.Authority.Bindings()
	if v.Organization.Present {
		return p.Authority.RequireOrganizationSession(ctx, w, owner, original)
	}
	return nil
}

// Lock authenticates no bearer. It fences original non-organization owners,
// acquires family SHARE then exact session UPDATE before organization locks,
// compares the complete original record and requires its original selection.
// The participant must call it before target organization/member admission.
// Every returned error must abort the participant's whole command.
func (e *OrganizationSelectionEffect) Lock(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	if ctx == nil || e == nil {
		return session.ErrInvalidSessionCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	c, until, _, err := e.intent(w, owner, command)
	if err != nil {
		return err
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := e.requirePrimary(bounded, w, owner, c.Binding, c.Source); err != nil {
		return err
	}
	s, _ := c.Source.Bindings()
	if err := e.native.requireIssueFamily(bounded, w, s, true); err != nil {
		return err
	}
	rows, err := w.Query(bounded, `SELECT record::text FROM `+e.native.schema+`.sessions WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3 AND version=$4::numeric AND state='active' FOR UPDATE`, string(s.TenantID), string(s.UserID), s.SessionID, strconv.FormatUint(s.Version, 10))
	if err != nil {
		return err
	}
	var locked []byte
	err = readSessionAdmission(rows, &locked)
	rows.Close()
	if err != nil {
		return admissionError(bounded, err)
	}
	if err := RequireSession(bounded, w, e.config, c.Source); err != nil {
		return err
	}
	if err := requireOriginalOrganization(bounded, w, owner, e.profile, c.Source); err != nil {
		return err
	}
	return oidcEndSessionWindow(bounded, w, c.Source, until)
}

// Apply performs the already-locked exact CAS and retains immutable session
// participant evidence. It changes only that session's version/vector, not its
// bearer, family, original authentication, activity or expiry. The organization
// participant must require target authority before this call and retain it
// through Check. No receipt or returned session is terminal before commit.
func (e *OrganizationSelectionEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) (identity.FeatureReceipt, error) {
	if err := e.Lock(ctx, w, owner, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	c, _, l, err := e.intent(w, owner, command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := requireOriginalOrganization(bounded, w, owner, e.profile, c.Successor); err != nil {
		return identity.FeatureReceipt{}, err
	}
	s, _ := c.Source.Bindings()
	n, _ := c.Successor.Bindings()
	before, _, err := encodeRecord(c.Source)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	after, _, err := encodeRecord(c.Successor)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	count, err := w.Exec(bounded, `UPDATE `+e.native.schema+`.sessions SET version=$1::numeric,record=$2::jsonb WHERE tenant_id=$3 AND user_id=$4 AND session_id=$5 AND version=$6::numeric AND state='active' AND record=$7::jsonb`, strconv.FormatUint(n.Version, 10), string(after), string(s.TenantID), string(s.UserID), s.SessionID, strconv.FormatUint(s.Version, 10), string(before))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if count != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	id, binding := organizationSelectionEvidence(c.Binding, l)
	sh, nh := sha256.Sum256(before), sha256.Sum256(after)
	count, err = w.Exec(bounded, `INSERT INTO `+e.native.schema+`.organization_selections(tenant_id,command_id,purpose,user_id,session_id,before_version,after_version,binding_digest,source_digest,successor_digest,source_record,successor_record) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8,$9,$10,$11::jsonb,$12::jsonb)`, string(s.TenantID), id, c.Binding.OperationID, string(s.UserID), s.SessionID, strconv.FormatUint(s.Version, 10), strconv.FormatUint(n.Version, 10), binding[:], sh[:], nh[:], string(before), string(after))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if count != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: session.OrganizationSelectionOperation(), BeforeVersion: s.Version, AfterVersion: n.Version}, nil
}

func organizationSelectionEvidence(b identity.CommandBinding, l kernel.LifecyclePlan) ([]byte, [32]byte) {
	id, binding := revocationEvidence(b, l)
	return id, sha256.Sum256(append([]byte("identity-session-organization-selection-v1\x00"), binding[:]...))
}

func (e *OrganizationSelectionEffect) selectHistory() string {
	return `SELECT purpose,user_id,session_id,before_version::text,after_version::text,binding_digest,source_digest,successor_digest,source_record::text,successor_record::text FROM ` + e.native.schema + `.organization_selections WHERE tenant_id=$1 AND command_id=$2`
}

func scanOrganizationSelection(row rotationScanner, b identity.CommandBinding, l kernel.LifecyclePlan) (session.OrganizationSelectionCommandSpec, error) {
	var purpose, user, id, before, after string
	var binding, sh, nh, sourceBytes, nextBytes []byte
	if err := row.Scan(&purpose, &user, &id, &before, &after, &binding, &sh, &nh, &sourceBytes, &nextBytes); err != nil {
		return session.OrganizationSelectionCommandSpec{}, err
	}
	deny := func() (session.OrganizationSelectionCommandSpec, error) {
		return session.OrganizationSelectionCommandSpec{}, session.ErrUnavailable
	}
	source, err := decodeRecord(sourceBytes)
	if err != nil {
		return deny()
	}
	next, err := decodeRecord(nextBytes)
	if err != nil {
		return deny()
	}
	s, _ := source.Bindings()
	n, _ := next.Bindings()
	v, _ := n.Authority.Bindings()
	mapped, err := session.NewOrganizationSelectionCommand(b, source, session.ActiveOrganizationSelection{TenantID: s.TenantID, SessionID: s.SessionID, SessionVersion: session.SessionVersion(s.Version), OrganizationID: v.ActiveOrganizationID, Authority: v.Organization.Binding})
	if err != nil {
		return deny()
	}
	c, _ := mapped.Bindings()
	canonicalSource, _, _ := encodeRecord(source)
	canonicalNext, _, _ := encodeRecord(next)
	expectedNext, _, _ := encodeRecord(c.Successor)
	_, expectedBinding := organizationSelectionEvidence(b, l)
	sourceHash, nextHash := sha256.Sum256(canonicalSource), sha256.Sum256(canonicalNext)
	if purpose != b.OperationID || user != string(b.UserID) || id != b.RecordID || before != strconv.FormatUint(l.BeforeVersion, 10) || after != strconv.FormatUint(l.AfterVersion, 10) || s.Version != l.BeforeVersion || n.Version != l.AfterVersion || !bytes.Equal(canonicalNext, expectedNext) || subtle.ConstantTimeCompare(binding, expectedBinding[:]) != 1 || subtle.ConstantTimeCompare(sh, sourceHash[:]) != 1 || subtle.ConstantTimeCompare(nh, nextHash[:]) != 1 {
		return deny()
	}
	return c, nil
}

// Check fences the successor, never the now-obsolete source CAS, and compares
// retained original evidence in the final commit fence. Every original primary
// owner and selected organization/member must remain current. The original
// admission deadline remains exclusive; final checks do not renew freshness.
func (e *OrganizationSelectionEffect) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	if ctx == nil || e == nil {
		return session.ErrInvalidSessionCommand
	}
	// RequireFeatureCommand is Apply-only. The commit invocation has its own
	// exact participant scope; compare retained source/successor below instead
	// of trying to reuse the expired Apply-generation handle.
	c, until, l, err := e.intent(w, owner, command)
	if err != nil {
		return err
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := e.requirePrimary(bounded, w, owner, c.Binding, c.Successor); err != nil {
		return err
	}
	if err := RequireSession(bounded, w, e.config, c.Successor); err != nil {
		return err
	}
	if err := requireOriginalOrganization(bounded, w, owner, e.profile, c.Successor); err != nil {
		return err
	}
	id, _ := organizationSelectionEvidence(c.Binding, l)
	rows, err := w.Query(bounded, e.selectHistory(), string(c.Binding.TenantID), id)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return rows.Err()
		}
		return identity.ForbiddenError{}
	}
	retained, err := scanOrganizationSelection(rows, c.Binding, l)
	if err != nil || rows.Next() || rows.Err() != nil {
		return session.ErrUnavailable
	}
	rows.Close()
	for _, pair := range [][2]session.Session{{retained.Source, c.Source}, {retained.Successor, c.Successor}} {
		a, _, _ := encodeRecord(pair[0])
		b, _, _ := encodeRecord(pair[1])
		if !bytes.Equal(a, b) {
			return session.ErrUnavailable
		}
	}
	return oidcEndSessionWindow(bounded, w, c.Successor, until)
}

// Recover votes from retained session-owned original transition evidence in
// the existing coordinator recovery Work. It never re-executes a CAS, requires
// a still-live session, authenticates history access or determines the overall
// command result; the organization service and coordinator retain those duties.
func (e *OrganizationSelectionEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || owner == nil {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, f, l, err := w.FeatureScope(owner)
	if err != nil || owner.Descriptor() != organizationSelectionOwner() || f.Contributor != organizationSelectionOwner() || f.Operation != session.OrganizationSelectionOperation() || l.EventType != "session.organization_changed.v1" || l.BeforeVersion == 0 || l.BeforeVersion == ^uint64(0) || l.AfterVersion != l.BeforeVersion+1 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	id, _ := organizationSelectionEvidence(b, l)
	rows, err := w.Query(bounded, e.selectHistory(), string(b.TenantID), id)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, rows.Err()
		}
		return kernel.RecoveryNotCommitted, nil
	}
	if _, err := scanOrganizationSelection(rows, b, l); err != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, session.ErrUnavailable
	}
	return kernel.RecoveryCommitted, nil
}

// Format redacts session and borrowed-owner configuration.
func (*OrganizationSelectionEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OrganizationSelectionEffect(redacted)"))
}

// MarshalJSON denies implicit effect disclosure.
func (*OrganizationSelectionEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
