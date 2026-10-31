//go:build unix

package repoagent

import (
	"os/exec"
	"syscall"
)

// killGroup place git dans son propre groupe de processus et tue tout le groupe à
// l'annulation : git lance des sous-processus (git-remote-https, index-pack) qui, sinon,
// survivraient à la commande.
func killGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
