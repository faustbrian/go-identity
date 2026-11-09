package oauth

import identity "github.com/faustbrian/go-identity"

// LinkCommand is the identity-owned immutable signed mutation intent. It carries
// stable command/tenant/subject/provider proof and expected versions, explicit
// final-access policy and copied logical contributors, without native SQL types.
// Construct through identity.NewLinkCommand; OAuth owns the ceremony, not links.
type LinkCommand = identity.LinkCommand

// LinkParticipants selects the injected authoritative linker and logical owners.
// The actual adapter resolves them inside its existing atomic unit of work.
type LinkParticipants = identity.LinkParticipants

// LinkResult separates provisional identity application from durable observation.
// Provider/token-vault state cannot turn the former into a committed link.
type LinkResult = identity.LinkResult

// AuthoritativeLinker is the identity-owned locked mutation contract:
// ApplyLink(context.Context, LinkCommand) (LinkResult, error). Only its owning
// unit of work binds invocation authority; unbound or escaped calls deny.
type AuthoritativeLinker = identity.AuthoritativeLinker

// LinkUnitOfWork is the neutral atomic contract:
// WithinLink(context.Context, LinkCommand, LinkParticipants) (LinkResult, error).
// It commits enlisted effects with the authoritative linker through the existing
// owner, never callback-ordering conventions or an OAuth-owned transaction engine.
type LinkUnitOfWork = identity.LinkUnitOfWork
