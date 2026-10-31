//go:build !linux

package hostagent

// uname n'est lu que sous Linux ; l'agent Windows (T22) aura sa propre source.
func uname() (release, machine string) { return "", "" }
