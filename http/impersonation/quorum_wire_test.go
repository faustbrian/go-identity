package impersonationhttp

import (
	"encoding/json"
	"testing"
)

func TestQuorumRejectsIncompleteConfiguration(t *testing.T) {
	if feature, err := NewQuorumFeature(QuorumConfig{}); err == nil || feature.ID() != "" {
		t.Fatal("incomplete quorum configuration selected a route")
	}
}

func TestQuorumWireDescribesCookieOnlyRead(t *testing.T) {
	wire := quorumWire("__Host-identity_session")
	var document struct {
		RequestBody json.RawMessage
		Parameters  []struct {
			In, Name string
			Required bool
		}
		Responses map[string]json.RawMessage
	}
	if err := json.Unmarshal(wire.Definition, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.RequestBody) != 0 || len(document.Parameters) != 1 ||
		document.Parameters[0].In != "query" || document.Parameters[0].Name != "grantID" ||
		!document.Parameters[0].Required || len(wire.SecuritySchemes) != 1 {
		t.Fatal("quorum must describe only the canonical query and ordinary cookie")
	}
	for _, status := range []string{"200", "400", "403", "421", "429", "503"} {
		if len(document.Responses[status]) == 0 {
			t.Fatalf("missing quorum response %s", status)
		}
	}
}
