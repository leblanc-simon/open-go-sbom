#!/bin/sh
# Avant désinstallation d'ogsbom-host-agent : arrêt et désactivation des unités, mais pas
# lors d'une mise à jour (deb : « upgrade » ; rpm : nombre d'installations restantes 1).
# L'état (/var/lib/ogsbom-host-agent, jeton d'agent compris) et l'utilisateur sont
# conservés, pour une réinstallation sans réinscription ; à supprimer à la main sinon.
set -e

case "$1" in
    remove|0) ;;
    *) exit 0 ;;
esac

if [ -d /run/systemd/system ]; then
    systemctl disable --now ogsbom-host-agent.service ogsbom-host-agent-oneshot.timer >/dev/null 2>&1 || true
fi
