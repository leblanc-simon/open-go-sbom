package pagination

import (
	"errors"
	"strings"
	"testing"
)

type key struct {
	Name string `json:"n"`
	ID   int    `json:"i"`
}

func TestLimit(t *testing.T) {
	ptr := func(n int) *int { return &n }
	if n, err := Limit(nil, 50, 200); n != 50 || err != nil {
		t.Fatalf("défaut : %d, %v", n, err)
	}
	if n, err := Limit(ptr(200), 50, 200); n != 200 || err != nil {
		t.Fatalf("maximum : %d, %v", n, err)
	}
	for _, bad := range []int{0, -1, 201} {
		_, err := Limit(ptr(bad), 50, 200)
		var le *LimitError
		if !errors.As(err, &le) || le.Max != 200 {
			t.Fatalf("Limit(%d) : err = %v", bad, err)
		}
	}
}

func TestCursorRoundTrip(t *testing.T) {
	in := key{Name: "élan/é", ID: 42}
	c, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c, version) || strings.ContainsAny(c, "+/= ") {
		t.Fatalf("curseur non sûr pour une URL : %q", c)
	}
	var out key
	if err := Decode(c, &out); err != nil || out != in {
		t.Fatalf("Decode = %+v, %v", out, err)
	}
}

func TestDecodeRefusesInvalidCursors(t *testing.T) {
	other, _ := Encode(map[string]any{"x": 1})
	valid, _ := Encode(key{"a", 1})
	cases := map[string]string{
		"vide":            "",
		"sans version":    strings.TrimPrefix(valid, version),
		"autre version":   "2." + strings.TrimPrefix(valid, version),
		"base64 invalide": version + "!!!",
		"JSON invalide":   version + "bm9u",
		"champ inconnu":   other,
		"données en trop": version + "eyJuIjoiYSIsImkiOjF9e30",
		"trop long":       version + strings.Repeat("A", MaxCursorLen),
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var out key
			if err := Decode(c, &out); !errors.Is(err, ErrInvalidCursor) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestBuild(t *testing.T) {
	rows := []key{{"a", 1}, {"b", 2}, {"c", 3}}
	keyOf := func(k key) any { return k }

	page, err := Build(rows, 3, keyOf)
	if err != nil || len(page.Items) != 3 || page.NextCursor != "" {
		t.Fatalf("dernière page : %+v, %v", page, err)
	}
	page, err = Build(rows, 2, keyOf)
	if err != nil || len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("page intermédiaire : %+v, %v", page, err)
	}
	var after key
	if err := Decode(page.NextCursor, &after); err != nil || after != rows[1] {
		t.Fatalf("curseur suivant = %+v, %v", after, err)
	}
	if _, err := Build(rows, 1, func(key) any { return func() {} }); err == nil {
		t.Fatal("clé non sérialisable acceptée")
	}
}
