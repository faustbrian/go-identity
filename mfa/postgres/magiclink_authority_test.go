package mfapostgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestMagicLinkFactorAuthorityRejectsNoNativeInvocation(t *testing.T) {
	if out,err:=RequireMagicLinkFactors(context.Background(),kernel.Work{},nil,identity.Command{},"user",0);err==nil || out.Version()!=0 {t.Fatal("metadata acquired factor authority")}
}
