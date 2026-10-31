#!/bin/sh
# Après installation d'ogsbom-host-agent : utilisateur système, droits du répertoire de
# configuration, rechargement de systemd. Les unités ne sont ni activées ni démarrées :
# il faut d'abord renseigner l'adresse du serveur et le jeton d'inscription.
set -e

if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/ogsbom-host-agent.conf
elif ! getent passwd ogsbom-agent >/dev/null; then
    useradd --system --home-dir /var/lib/ogsbom-host-agent --no-create-home \
        --shell /usr/sbin/nologin --comment "open-go-sbom host agent" ogsbom-agent
fi

# Le jeton d'inscription y est déposé par l'administrateur, lisible du seul agent.
chown root:ogsbom-agent /etc/ogsbom-host-agent
chmod 0750 /etc/ogsbom-host-agent

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    # Mise à jour : un démon déjà actif repart sur le nouveau binaire.
    systemctl try-restart ogsbom-host-agent.service || true
fi
