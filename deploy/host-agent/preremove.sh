#!/bin/sh
# Avant désinstallation d'lotor-host-agent : arrêt et désactivation des unités, mais pas
# lors d'une mise à jour (deb : « upgrade » ; rpm : nombre d'installations restantes 1).
# L'état (/var/lib/lotor-host-agent, jeton d'agent compris) et l'utilisateur sont
# conservés, pour une réinstallation sans réinscription ; à supprimer à la main sinon.
set -e

case "$1" in
    remove|0) ;;
    *) exit 0 ;;
esac

if [ -d /run/systemd/system ]; then
    systemctl disable --now lotor-host-agent.service lotor-host-agent-oneshot.timer >/dev/null 2>&1 || true
fi
