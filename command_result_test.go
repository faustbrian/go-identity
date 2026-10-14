package identity

import "testing"

func TestCommandResultValidate(t *testing.T) {
	b := CommandBinding{CommandID: "AAAAAAAAAAAAAAAAAAAAAQ", TenantID: "tenant", UserID: "user", ActorID: "actor", ActorKind: "user", OperationID: "identity.user.create", PolicyID: "policy", PolicyVersion: 1, SchemaID: "profile", SchemaVersion: 1, CorrelationID: "correlation"}
	r := CommandResult{Binding: b, Outcome: CommitOutcomeCommitted, User: User{ID: b.UserID, TenantID: b.TenantID, Status: StatusActive, Version: 1}, AuditEventID: "audit"}
	if e := r.Validate(); e != nil {
		t.Fatal("valid creation receipt rejected")
	}
	r.User.Version = 2
	if e := r.Validate(); e == nil {
		t.Fatal("invalid creation version accepted")
	}
	r = CommandResult{Binding: b, Outcome: CommitOutcomeNotCommitted}
	if e := r.Validate(); e != nil {
		t.Fatal("valid abort receipt rejected")
	}
	if e := (CommandResult{}).Validate(); e == nil {
		t.Fatal("zero receipt accepted")
	}
}
