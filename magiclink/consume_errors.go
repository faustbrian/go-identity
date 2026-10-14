package magiclink

// SupersededError denotes an authenticated original link replaced by a later
// request for the same recipient and browser flow. Native consumers return it
// only after validating the caller's original browser and signed scope. It
// conveys neither account existence nor permission to retry or create a session.
// Transactional consumption remains authoritative if supersession races a read.
type SupersededError struct{}

// Error returns a stable redacted classification without correlated metadata.
func (SupersededError) Error() string { return "magiclink: link superseded" }
