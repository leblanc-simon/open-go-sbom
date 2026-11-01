#!/bin/sh
set -eu
# Outils de la CI.
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b /usr/local/bin v1.59.1
curl -sSfL -o /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64
chmod +x /usr/local/bin/hadolint
