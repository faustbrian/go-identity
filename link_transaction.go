package identity

import (
	"context"
	"fmt"
	"slices"
)

// LinkFinalAccessPolicy identifies a closed, versioned identity transition
// policy, not caller authorization. Zero is invalid. Additional policies require
// an owning transition and adapter admission; unknown policies never default.
type LinkFinalAccessPolicy uint8

// LinkPreserveExistingAccess is the v1 additive-link policy implemented by
// ApplyAccountLink: existing accounts and login methods are conserved. It does
// not enable unlink, forced transfer, implicit linking or administrative access.
const LinkPreserveExistingAccess LinkFinalAccessPolicy = 1

// LinkContributor names one logical owner and its selected contract revision.
// It contains no adapter, transaction handle, credentials or authority. Order is
// significant and must match the unit of work's frozen participant declaration.
type LinkContributor struct {
	Owner, ContractID string
	Version           uint64
}

// LinkCommand is immutable storage-neutral final link intent. It preserves the
// existing signed command, provider/account tuple, actor/tenant/subject, expected
// versions and browser binding together with explicit access policy and logical
// owners. It grants no transaction, provider, policy or consumption authority.
// Copies support concurrent reads; there is no cleanup or execution lifetime.
type LinkCommand struct{ state *linkTransactionIntent }

type linkTransactionIntent struct {
	command      Command
	policy       LinkFinalAccessPolicy
	contributors []LinkContributor
}

// NewLinkCommand snapshots an already constructed link command and 1..32
// distinct logical contributors. Bare and protected-counter variants preserve
// their existing wire and proof semantics. Preparation-only input, unrelated
// commands and unspecified access policies fail with no intent. This pure
// constructor performs no verification, callbacks, IO or authorization.
func NewLinkCommand(command Command, policy LinkFinalAccessPolicy, owners []LinkContributor) (LinkCommand, error) {
	if policy != LinkPreserveExistingAccess || !validLinkContributors(owners) {
		return LinkCommand{}, invalidLinkTransaction()
	}
	spec, counters, counted := command.AccountLinkCounterCommand()
	if !counted {
		var ok bool
		spec, ok = command.LinkAccount()
		if !ok {
			return LinkCommand{}, invalidLinkTransaction()
		}
	}
	owned, err := NewAccountLinkCommand(spec)
	if err != nil {
		return LinkCommand{}, invalidLinkTransaction()
	}
	if counted {
		owned, err = NewAccountLinkCounterCommand(owned, counters)
		if err != nil {
			return LinkCommand{}, invalidLinkTransaction()
		}
	}
	return LinkCommand{&linkTransactionIntent{command: owned, policy: policy, contributors: slices.Clone(owners)}}, nil
}

// Command returns the original opaque root command, or false for zero. Its
// typed projections retain their existing defensive-copy and proof contracts.
func (c LinkCommand) Command() (Command, bool) {
	if c.state == nil {
		return Command{}, false
	}
	return c.state.command, true
}

// FinalAccessPolicy returns the selected versioned policy, or zero for zero.
func (c LinkCommand) FinalAccessPolicy() LinkFinalAccessPolicy {
	if c.state == nil {
		return 0
	}
	return c.state.policy
}

// Contributors returns an owned ordered copy, or nil for zero.
func (c LinkCommand) Contributors() []LinkContributor {
	if c.state == nil {
		return nil
	}
	return slices.Clone(c.state.contributors)
}

// AuthoritativeLinker owns the locked identity transition inside the selected
// unit of work. ApplyLink returns provisional application only; it cannot
// independently commit. Unbound, escaped or foreign invocation authority denies.
// Concrete adapters bind invocation-local receivers, not context values or
// mutable state on a shared repository. Calls honor cancellation and earlier
// native budgets; consumers cannot substitute provider proof for current state.
type AuthoritativeLinker interface {
	ApplyLink(context.Context, LinkCommand) (LinkResult, error)
}

// LinkUnitOfWork owns atomic participant execution and durable observation.
// It validates exact command, policy and owner selection before applying the
// injected authoritative linker and committing all required effects together.
// Unknown outcomes reveal no successful application or account projection.
// Concrete one-use execution handles document their reservation/retry lifetime.
type LinkUnitOfWork interface {
	WithinLink(context.Context, LinkCommand, LinkParticipants) (LinkResult, error)
}

// LinkParticipants is immutable injected owner selection, not a transaction or
// callback-ordering protocol. The UoW resolves these logical identities against
// its actual registered adapters; the caller cannot invent a matching authority.
// The linker is borrowed and must remain usable for the selected invocation.
type LinkParticipants struct {
	linker       AuthoritativeLinker
	contributors []LinkContributor
}

// NewLinkParticipants snapshots a nonnil linker and 1..32 distinct ordered
// logical owners. Typed nil is rejected. No collaborator is invoked here.
func NewLinkParticipants(linker AuthoritativeLinker, owners []LinkContributor) (LinkParticipants, error) {
	if nilDependency(linker) || !validLinkContributors(owners) {
		return LinkParticipants{}, invalidLinkTransaction()
	}
	return LinkParticipants{linker: linker, contributors: slices.Clone(owners)}, nil
}

// Linker returns the selected borrowed authority, nil for zero. This projection
// is not permission to call it outside its owning unit-of-work invocation.
func (p LinkParticipants) Linker() AuthoritativeLinker { return p.linker }

// Contributors returns an owned ordered selection, nil for zero.
func (p LinkParticipants) Contributors() []LinkContributor { return slices.Clone(p.contributors) }

// LinkApplication is provisional identity-owned mutation metadata, never a
// commit outcome. The unit of work must still finalize required effects and
// obtain an acknowledged durable commit before delivering a successful receipt.
type LinkApplication struct {
	Binding         CommandBinding
	User            User
	ExpectedVersion uint64
	Link            AccountLinkReceipt
	AuditEventID    string
}

// LinkResult distinguishes provisional application from durable observation.
// Zero has neither variant. Its projections are metadata, not current access,
// receipt lookup authority or permission to retry exchange or mutation.
type LinkResult struct {
	application *LinkApplication
	receipt     *CommandResult
}

// NewAppliedLinkResult validates a complete provisional root link projection.
// It does not verify a signature, run a transition or prove commitment. Only
// the enlisted authoritative writer may supply this result to its owning UoW.
func NewAppliedLinkResult(application LinkApplication) (LinkResult, error) {
	r := CommandResult{Binding: application.Binding, User: application.User, ExpectedVersion: application.ExpectedVersion, Outcome: CommitOutcomeCommitted, Link: &application.Link, AuditEventID: application.AuditEventID}
	if !validObservedLink(r) {
		return LinkResult{}, invalidLinkTransaction()
	}
	return LinkResult{application: &application}, nil
}

// NewObservedLinkResult validates and copies an authoritative scoped command
// observation, including noncommit and unknown. This structural constructor
// cannot establish storage provenance or authorization. Adapters must obtain
// those facts from their sole durable owner before public delivery.
func NewObservedLinkResult(receipt CommandResult) (LinkResult, error) {
	if !validObservedLink(receipt) {
		return LinkResult{}, invalidLinkTransaction()
	}
	if receipt.Link != nil {
		link := *receipt.Link
		receipt.Link = &link
	}
	return LinkResult{receipt: &receipt}, nil
}

// Application returns a provisional owned projection only, never a receipt.
func (r LinkResult) Application() (LinkApplication, bool) {
	if r.application == nil {
		return LinkApplication{}, false
	}
	return *r.application, true
}

// Receipt returns an owned durable observation only. A provisional application
// returns false; Unknown retains its empty protected-result payload.
func (r LinkResult) Receipt() (CommandResult, bool) {
	if r.receipt == nil {
		return CommandResult{}, false
	}
	out := *r.receipt
	if out.Link != nil {
		link := *out.Link
		out.Link = &link
	}
	return out, true
}

func validObservedLink(r CommandResult) bool {
	return r.Binding.OperationID == "identity.account.link-token" && r.Validate() == nil && r.Feature == nil && r.Cascade == nil && r.PrivacyExport == nil
}

func validLinkContributors(owners []LinkContributor) bool {
	if len(owners) == 0 || len(owners) > 32 {
		return false
	}
	for i, owner := range owners {
		if !validDirectoryID(owner.Owner) || !validDirectoryID(owner.ContractID) || owner.Version == 0 || slices.Contains(owners[:i], owner) {
			return false
		}
	}
	return true
}

func invalidLinkTransaction() error { return InvalidInputError{Field: "link_transaction"} }

// Format omits the original provider/account/browser and proof correlations.
func (LinkCommand) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identity.LinkCommand(redacted)"))
}

// MarshalJSON refuses implicit command export.
func (LinkCommand) MarshalJSON() ([]byte, error) { return nil, invalidLinkTransaction() }

// MarshalText refuses implicit text or map-key export.
func (LinkCommand) MarshalText() ([]byte, error) { return nil, invalidLinkTransaction() }

// Format hides borrowed transaction-participant selection.
func (LinkParticipants) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identity.LinkParticipants(redacted)"))
}

// MarshalJSON refuses implicit participant export.
func (LinkParticipants) MarshalJSON() ([]byte, error) { return nil, invalidLinkTransaction() }

// MarshalText refuses implicit participant text export.
func (LinkParticipants) MarshalText() ([]byte, error) { return nil, invalidLinkTransaction() }

// Format hides provisional or durable identity correlations.
func (LinkResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identity.LinkResult(redacted)"))
}

// MarshalJSON refuses implicit result export.
func (LinkResult) MarshalJSON() ([]byte, error) { return nil, invalidLinkTransaction() }

// MarshalText refuses implicit result text export.
func (LinkResult) MarshalText() ([]byte, error) { return nil, invalidLinkTransaction() }

// Format hides provisional identity mutation metadata.
func (LinkApplication) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identity.LinkApplication(redacted)"))
}

// MarshalJSON refuses provisional mutation export.
func (LinkApplication) MarshalJSON() ([]byte, error) { return nil, invalidLinkTransaction() }

// MarshalText refuses provisional mutation text export.
func (LinkApplication) MarshalText() ([]byte, error) { return nil, invalidLinkTransaction() }
