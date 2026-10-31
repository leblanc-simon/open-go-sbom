package search

import (
	"net/url"
	"testing"
	"unicode/utf8"
)

// FuzzParse : sur toute entrée, l'analyseur de requête ne panique pas et ne renvoie que
// des refus traduisibles ; une requête acceptée garde ses bornes, se décrit (Tokens) et se
// relit à l'identique depuis sa forme normalisée.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"log4j-core", "pkg:npm/lodash vers:npm/<4.17.21", "CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q",
		"sha256:0925e8ad7bd971391a8b1e98be8e87a6971919eb5b60c196485941c3c1df089a", "license:MIT",
		"pkg:deb/debian/openssl?arch=amd64", "vers:npm/*", "pkg:npm/a vers:npm/>=1|<2", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		q, err := Parse(raw, cmp)
		if err != nil {
			if _, ok := IsError(err); !ok {
				t.Fatalf("%q : erreur sans clé %v", raw, err)
			}
			return
		}
		if !utf8.ValidString(q.Raw) || len(q.Raw) > MaxQueryLen || len(q.Tokens()) == 0 {
			t.Fatalf("%q : requête %+v", raw, q)
		}
		again, err := Parse(q.Raw, cmp)
		if err != nil || again.Kind != q.Kind || again.Name != q.Name || again.VulnID != q.VulnID || again.Hash != q.Hash ||
			again.PURL.PURL != q.PURL.PURL || (again.Range == nil) != (q.Range == nil) {
			t.Fatalf("%q relue autrement : %+v, %v", q.Raw, again, err)
		}
		if q.Range != nil && again.Range.String() != q.Range.String() {
			t.Fatalf("plage relue autrement : %s ≠ %s", again.Range, q.Range)
		}
	})
}

// FuzzParseRequest : des paramètres d'URL quelconques ne font pas paniquer la lecture, et
// une recherche acceptée se relit à l'identique depuis ses paramètres.
func FuzzParseRequest(f *testing.F) {
	f.Add("q=x&type=repo&label=env%3Dprod&kev=1&severity=none&sort=name")
	f.Add("label=a%3Db%2Cc&origin=ia")
	f.Fuzz(func(t *testing.T, raw string) {
		v, err := url.ParseQuery(raw)
		if err != nil {
			return
		}
		r, err := ParseRequest(v)
		if err != nil {
			return
		}
		again, err := ParseRequest(r.Values())
		if err != nil || again.Values().Encode() != r.Values().Encode() {
			t.Fatalf("%q : %v, %v", raw, again.Values(), err)
		}
	})
}
