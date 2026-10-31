package tenant

import (
	"context"
	"errors"
	"testing"
)

func TestRoleOrder(t *testing.T) {
	cases := []struct {
		role, min Role
		want      bool
	}{
		{RoleAdmin, RoleViewer, true}, {RoleAdmin, RoleAdmin, true}, {RoleAnalyst, RoleViewer, true},
		{RoleViewer, RoleAnalyst, false}, {RoleAnalyst, RoleAdmin, false}, {"chef", RoleViewer, false},
	}
	for _, c := range cases {
		if got := c.role.AtLeast(c.min); got != c.want {
			t.Errorf("%s ≥ %s : %v", c.role, c.min, got)
		}
	}
	for _, r := range Roles() {
		if got, err := ParseRole(string(r)); err != nil || got != r {
			t.Errorf("%s : %v", r, err)
		}
	}
	if _, err := ParseRole("chef"); !errors.Is(err, ErrInvalidRole) {
		t.Fatal(err)
	}
}

func TestAccessContext(t *testing.T) {
	if _, ok := AccessFrom(context.Background()); ok {
		t.Fatal("accès dans un contexte vide")
	}
	org, _ := NewOrgID()
	ctx := WithAccess(context.Background(), Access{Org: org, Slug: "a", Role: RoleViewer})
	a, ok := AccessFrom(ctx)
	if !ok || a.Slug != "a" {
		t.Fatalf("%+v", a)
	}
	if got, ok := FromContext(ctx); !ok || got != org {
		t.Fatal("organisation absente du contexte")
	}
}
