package web

import (
	"net/http"
	"strings"
)

// installStep est une étape de l'assistant d'installation de l'agent serveur : un texte
// traduit et des commandes, qui ne se traduisent pas.
type installStep struct {
	TitleKey string
	Commands []string
	HintKey  string
}

// serverURL est l'adresse du serveur telle que le navigateur l'a jointe ; l'agent ne parle
// qu'en HTTPS.
func serverURL(r *http.Request) string { return "https://" + r.Host }

// shellQuote cite une valeur pour un shell POSIX.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// hostAgentInstall décrit l'installation d'lotor-host-agent avec un jeton d'inscription
// (paquets et unités de deploy/, chemins de docs/operations.md, « Agent serveur »).
func hostAgentInstall(server, token string) []installStep {
	return []installStep{
		{TitleKey: "host_install.package", Commands: []string{
			"sudo apt install ./lotor-host-agent_<version>_amd64.deb",
			"sudo dnf install ./lotor-host-agent-<version>.x86_64.rpm",
		}, HintKey: "host_install.package_hint"},
		{TitleKey: "host_install.server", Commands: []string{
			"sudo sed -i 's|^  url: .*|  url: " + server + "|' /etc/lotor-host-agent/config.yaml",
		}, HintKey: "host_install.server_hint"},
		{TitleKey: "host_install.token", Commands: []string{
			"printf '%s' " + shellQuote(token) + " | sudo install -m 0600 -o lotor-agent -g lotor-agent /dev/stdin /etc/lotor-host-agent/enrollment-token",
		}, HintKey: "host_install.token_hint"},
		{TitleKey: "host_install.start", Commands: []string{
			"sudo systemctl enable --now lotor-host-agent.service",
		}, HintKey: "host_install.start_hint"},
		{TitleKey: "host_install.cleanup", Commands: []string{
			"sudo rm /etc/lotor-host-agent/enrollment-token",
		}},
	}
}
