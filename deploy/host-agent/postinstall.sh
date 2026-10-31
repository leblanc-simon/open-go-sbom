#!/bin/sh
# Après installation de lotor-host-agent : utilisateur système, droits du répertoire de
# configuration, rechargement de systemd. Les unités ne sont ni activées ni démarrées :
# il faut d'abord renseigner l'adresse du serveur et le jeton d'inscription.
set -e

if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/lotor-host-agent.conf
elif ! getent passwd lotor-agent >/dev/null; then
    useradd --system --home-dir /var/lib/lotor-host-agent --no-create-home \
        --shell /usr/sbin/nologin --comment "lotor host agent" lotor-agent
fi

# Le jeton d'inscription y est déposé par l'administrateur, lisible du seul agent.
chown root:lotor-agent /etc/lotor-host-agent
chmod 0750 /etc/lotor-host-agent

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    # Mise à jour : un démon déjà actif repart sur le nouveau binaire.
    systemctl try-restart lotor-host-agent.service || true
fi
