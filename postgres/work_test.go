package postgres

import (
	"bytes"
	"context"
	"math"
	"strings"
	"testing"
)

func TestWorkZeroCannotExecute(t *testing.T) {
	var w Work
	if _, err := w.Scope(); err == nil {
		t.Fatal("zero scope accepted")
	}
	if _, err := w.Exec(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero executed")
	}
	if rows, err := w.Query(context.Background(), "SELECT 1"); rows != nil || err == nil {
		t.Fatal("zero queried")
	}
	if _, err := w.DatabaseTime(context.Background()); err == nil {
		t.Fatal("zero read database time")
	}
}

func TestWorkRowsZeroCannotRead(t *testing.T) {
	for _, rows := range []*WorkRows{nil, {}} {
		if rows.Next() {
			t.Fatal("zero rows advanced")
		}
		if rows.Scan(new(int32)) == nil || rows.Err() == nil {
			t.Fatal("zero rows accepted")
		}
		rows.Close()
		rows.Close()
	}
}

func TestWorkParametersPreserveEmptyBytes(t *testing.T) {
	input := []byte{}
	args, err := workParameters("SELECT $1::bytea", []any{input})
	if err != nil || args[0].([]byte) == nil {
		t.Fatal("empty bytes became SQL NULL")
	}
	input = []byte{1, 2}
	args, err = workParameters("SELECT $1::bytea", []any{input})
	input[0] = 9
	if err != nil || !bytes.Equal(args[0].([]byte), []byte{1, 2}) {
		t.Fatal("parameter storage aliased")
	}
}

func TestWorkInputBudgets(t *testing.T) {
	for _, args := range [][]any{{math.NaN()}, {math.Inf(1)}, {new(string)}, {strings.Repeat("x", (1<<20)+1)}, make([]any, 65)} {
		if _, err := workParameters("SELECT 1", args); err == nil {
			t.Fatal("unsafe parameter accepted")
		}
	}
	for _, sql := range []string{"", "COMMIT", strings.Repeat("x", 65537), "SELECT\x00", "\xffSELECT 1"} {
		if _, err := workParameters(sql, nil); err == nil {
			t.Fatal("unsafe SQL accepted")
		}
	}
	var nilString *string
	if workDestinations([]any{nilString}) || workDestinations([]any{new(any)}) {
		t.Fatal("unsafe scan accepted")
	}
}

func FuzzWorkParameters(f *testing.F) {
	f.Add("SELECT $1::text", "bounded")
	f.Add("COMMIT", "")
	f.Add("\xffSELECT", "x")
	f.Fuzz(func(t *testing.T, sql, value string) {
		args, err := workParameters(sql, []any{value})
		if err != nil {
			if err.Error() != "identity: invalid input" {
				t.Fatal("unredacted error")
			}
			return
		}
		if len(sql) > 65536 || len(value) > 1<<20 || len(args) != 1 || args[0] != value {
			t.Fatal("parameters lost identity/bounds")
		}
	})
}
