//go:build !unix

package repoagent

import "os/exec"

// killGroup : hors Unix, seul le processus git lui-même est tué à l'annulation.
func killGroup(*exec.Cmd) {}
