# Outils de développement, téléchargés à la demande.
ARCH ?= $(shell uname -m)

GOTESTSUM_VERSION := 1.12.0
GOTESTSUM_FILE := support/bin/gotestsum-${GOTESTSUM_VERSION}

.PHONY: test
test: ${GOTESTSUM_FILE}
	${GOTESTSUM_FILE} -- ./...

${GOTESTSUM_FILE}:
	mkdir -p support/bin
	curl -L https://github.com/gotestyourself/gotestsum/releases/download/v${GOTESTSUM_VERSION}/gotestsum_${GOTESTSUM_VERSION}_linux_${ARCH}.tar.gz | tar -zOxf - gotestsum > $@
	chmod +x $@

.PHONY: lint
lint:
	go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...
