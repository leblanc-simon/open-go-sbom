package grypeversion

import (
	"errors"
	"testing"

	"leblanc.io/lotor/internal/version"
)

// FuzzCompare : sur toute entrée, le comparateur ne panique pas, renvoie un signe, et
// reste antisymétrique ; une erreur est toujours ErrNotComparable.
func FuzzCompare(f *testing.F) {
	for _, s := range []string{"1.0", "v1.2.3", "1:2.36-9", "1.0~rc1", "1.0-r0", "1.0a1", "2.14.1", "", "latest", "1!2.0.post1"} {
		f.Add(s, "1.0.0")
	}
	c := New()
	f.Fuzz(func(t *testing.T, a, b string) {
		for _, s := range version.Schemes() {
			n, err := c.Compare(s, a, b)
			if err != nil {
				if !errors.Is(err, version.ErrNotComparable) {
					t.Fatalf("%s : erreur inattendue %v", s, err)
				}
				continue
			}
			if n < -1 || n > 1 {
				t.Fatalf("%s : %q ? %q = %d", s, a, b, n)
			}
			if m, err := c.Compare(s, b, a); err == nil && m != -n {
				t.Fatalf("%s : %q ? %q = %d mais %q ? %q = %d", s, a, b, n, b, a, m)
			}
		}
	})
}
