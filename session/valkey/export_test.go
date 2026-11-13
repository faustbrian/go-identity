package sessionvalkey

// ActiveForTest observes the existing synchronization owner, not a test-only
// production hook. It makes cancellation testing wait for actual admission.
func ActiveForTest(c *Cache) bool { return c != nil && len(c.sem) > 0 }
