package postgres

import (
	"context"
	"fmt"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// PrivacyExportAdmissionContributor is the registered native session owner's
// read-only check for a frozen self-service privacy request. Checks must use
// the original session/version and all applicable primary authority owners.
// This role cannot attest mutation outcome, refresh evidence, consume proof,
// write rows, retain Work, open transactions or perform network IO. Its methods
// must support concurrent invocations with separate serial-use handles.
type PrivacyExportAdmissionContributor interface {
	Contributor
	CheckPrivacyExport(context.Context, PrivacyExportAdmissionWork) error
}

type privacyAdmissionProgress struct {
	command                        identity.PrivacyExportRequestCommand
	digest                         [32]byte
	initialDone, finalDone, active bool
}
type privacyAdmissionState struct {
	work          Work
	participant   PrivacyExportAdmissionContributor
	command       identity.PrivacyExportRequestCommand
	final, active bool
}

// PrivacyExportAdmissionWork borrows the original generation-bound transaction
// solely during its exact registered invocation. It exposes bounded reads and
// existing kernel checks, never writes or closure. Zero/retained handles deny;
// copies share serial invocation lifetime. Errors on live handles poison the
// original Work, even when ignored. Initial/final checks cannot renew original
// session/proof expiry or authoritative evidence. This is not authentication.
type PrivacyExportAdmissionWork struct{ state *privacyAdmissionState }

// Format redacts session/proof/transaction correlations for every verb.
func (PrivacyExportAdmissionWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PrivacyExportAdmissionWork(redacted)"))
}

// MarshalJSON rejects serialization of invocation authority.
func (PrivacyExportAdmissionWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects implicit serialization of invocation authority.
func (PrivacyExportAdmissionWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

func (h PrivacyExportAdmissionWork) usable() error {
	if h.state == nil || !h.state.active {
		return invalidWork()
	}
	return h.state.work.usable()
}
func (h PrivacyExportAdmissionWork) deny() error {
	if h.state == nil || !h.state.active {
		return invalidWork()
	}
	return h.state.work.fail(h.state.work.state.ctx, invalidWork())
}
func (h PrivacyExportAdmissionWork) failure(ctx context.Context, err error) error {
	if err != nil {
		return h.state.work.fail(ctx, err)
	}
	return nil
}

// Command returns an owned projection copy and the terminal-recheck flag only
// to the exact selected participant. Expected identity/authority/session fields
// are always the original request, never a newer session or refreshed vector.
func (h PrivacyExportAdmissionWork) Command(p PrivacyExportAdmissionContributor) (identity.PrivacyExportRequestCommand, bool, error) {
	if err := h.usable(); err != nil {
		return identity.PrivacyExportRequestCommand{}, false, err
	}
	if !sameParticipant(p, h.state.participant) {
		return identity.PrivacyExportRequestCommand{}, false, h.deny()
	}
	c := h.state.command
	c.Projections = slices.Clone(c.Projections)
	return c, h.state.final, nil
}

// Query executes one bounded trusted primary query with Work's existing limits.
// Close rows before returning; this is not an application SQL sandbox.
func (h PrivacyExportAdmissionWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := h.usable(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, h.deny()
	}
	rows, err := h.state.work.Query(ctx, sql, args...)
	return rows, h.failure(ctx, err)
}

// DatabaseTime samples primary time without restarting any validity interval.
func (h PrivacyExportAdmissionWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := h.usable(); err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, h.deny()
	}
	now, err := h.state.work.DatabaseTime(ctx)
	return now, h.failure(ctx, err)
}

// RequireActiveCredential borrows exact kernel credential/user epoch checks;
// their primary locks remain until the original coordinator transaction closes.
func (h PrivacyExportAdmissionWork) RequireActiveCredential(ctx context.Context, p PrivacyExportAdmissionContributor, e CredentialAdmission) (time.Time, error) {
	c, _, err := h.Command(p)
	if err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, h.deny()
	}
	now, err := h.state.work.requireActiveCredential(ctx, c.Binding, e)
	return now, h.failure(ctx, err)
}

// RequireActiveDirectoryAuthority checks configured global/tenant epochs without
// adopting a newer authority or claiming policy Allow.
func (h PrivacyExportAdmissionWork) RequireActiveDirectoryAuthority(ctx context.Context, p PrivacyExportAdmissionContributor, e DirectoryAuthorityAdmission) error {
	c, _, err := h.Command(p)
	if err != nil {
		return err
	}
	if ctx == nil {
		return h.deny()
	}
	return h.failure(ctx, h.state.work.requireActiveDirectoryAuthority(ctx, c.Binding, e))
}

// RequireActiveUserAuthorization borrows the existing authorization owner's
// primary checks; it does not create a separate identity policy engine.
func (h PrivacyExportAdmissionWork) RequireActiveUserAuthorization(ctx context.Context, p PrivacyExportAdmissionContributor, e UserAuthorizationAdmission) error {
	c, _, err := h.Command(p)
	if err != nil {
		return err
	}
	if ctx == nil {
		return h.deny()
	}
	return h.failure(ctx, h.state.work.requireActiveUserAuthorization(ctx, c.Binding, e))
}

// Private invocation plumbing, not a new executable public command profile.
// Complete protected plan/proof/cut/effect/recovery composition is still needed
// before Prepare/Begin may admit a privacy command or any worker may run it.
func runPrivacyExportAdmission(ctx context.Context, w Work, c identity.PrivacyExportRequestCommand, final bool) (err error) {
	if err = w.usable(); err != nil {
		return err
	}
	fail := func(e error) error { return w.fail(w.state.ctx, e) }
	if ctx == nil || c.Binding != w.state.binding || w.state.registry == nil {
		return fail(invalidWork())
	}
	if err = ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	digest, e := identity.PrivacyExportIntentDigest(c)
	if e != nil {
		return fail(invalidWork())
	}
	entries, e := (&ContributorRegistry{state: w.state.registry}).selectContributors([]ContributorDescriptor{identifierAdmissionDescriptor()})
	if e != nil {
		return fail(invalidPlan())
	}
	p, ok := entries[0].contributor.(PrivacyExportAdmissionContributor)
	if !ok || !sameParticipant(p, p) {
		return fail(invalidPlan())
	}
	progress := w.state.privacyAdmission
	if final {
		a, r := w.state.privacyAllocation, w.state.privacyReceipt
		if progress == nil || !progress.initialDone || progress.finalDone || progress.active || progress.digest != digest || progress.command.Proof.EnvelopeDigest() != c.Proof.EnvelopeDigest() || a == nil || r == nil || a.intentDigest != digest || r.IntentDigest != digest || r.Status != identity.PrivacyExportQueued || a.privacyEpoch != c.ExpectedPrivacyEpoch+1 || a.identityVersion != c.ExpectedIdentityVersion || a.authorityVersion != c.ExpectedAuthorityVersion || r.Snapshot.ExportID != a.exportID || r.Snapshot.PrivacyEpoch != a.privacyEpoch || r.Snapshot.IdentityVersion != a.identityVersion || r.Snapshot.TenantID != c.Binding.TenantID || r.Snapshot.SubjectID != c.Binding.UserID || r.Snapshot.CommandID != c.Binding.CommandID || r.Snapshot.RequestedAtMicroseconds != a.requestedAtMicroseconds {
			return fail(invalidWork())
		}
	} else {
		if progress != nil || w.state.privacyAllocation != nil || w.state.privacyReceipt != nil {
			return fail(invalidWork())
		}
		c.Projections = slices.Clone(c.Projections)
		progress = &privacyAdmissionProgress{command: c, digest: digest}
		w.state.privacyAdmission = progress
	}
	progress.active = true
	s := &privacyAdmissionState{work: w, participant: p, command: progress.command, final: final, active: true}
	defer func() {
		s.active = false
		progress.active = false
		if recover() != nil {
			err = fail(identity.UnavailableError{})
		}
	}()
	if e = p.CheckPrivacyExport(ctx, PrivacyExportAdmissionWork{state: s}); e != nil {
		_, _, _, safe := abortClassification(e)
		return fail(safe)
	}
	if e = ctx.Err(); e != nil {
		return w.fail(ctx, e)
	}
	if w.state.rows != nil {
		return fail(identity.UnavailableError{})
	}
	if e = w.usable(); e != nil {
		return e
	}
	if final {
		progress.finalDone = true
	} else {
		progress.initialDone = true
	}
	return nil
}
