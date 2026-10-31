# Cibles de développement d'open-go-sbom. `make ci` exécute exactement ce que fait la CI.

GO        ?= go
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo develop)
LDFLAGS   := -s -w -X 'main.version=$(VERSION)'
BINARIES  := ogsbom-server ogsbom-host-agent ogsbom-repo-agent
GOOS      ?= $(shell $(GO) env GOOS)
GOARCH    ?= $(shell $(GO) env GOARCH)

# Code généré, vérifié à jour par generate-check.
GENERATED := internal/api/gen internal/agentclient/gen

# Connexion d'administration des tests d'intégration (deploy/compose.yaml) : chaque test
# y crée sa base et ses rôles jetables.
OGSBOM_TEST_DATABASE_DSN ?= postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable
export OGSBOM_TEST_DATABASE_DSN

.DEFAULT_GOAL := help

.PHONY: help
help: ## Liste les cibles
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-18s %s\n", $$1, $$2}'

.PHONY: build
build: ## Construit les trois binaires dans bin/
	@mkdir -p bin
	@for b in $(BINARIES); do \
		echo "build $$b ($(GOOS)/$(GOARCH), $(VERSION))"; \
		CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/$$b ./cmd/$$b || exit 1; \
	done

# Agent serveur : architectures livrées et version des paquets : celle de l'étiquette sans
# son « v », sinon 0.0.0~<commit> (une version deb ou rpm commence par un chiffre).
AGENT_ARCHES := amd64 arm64
PKG_VERSION  := $(shell echo '$(VERSION)' | sed -E 's/^v//; /^[0-9]+[.][0-9]/!s/^/0.0.0~/; s/-/./g')

.PHONY: packages
packages: ## Binaires de l'agent serveur (amd64, arm64) et paquets deb et rpm dans dist/
	@mkdir -p dist
	@for a in $(AGENT_ARCHES); do \
		echo "build ogsbom-host-agent (linux/$$a, $(VERSION))"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$a $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/linux-$$a/ogsbom-host-agent ./cmd/ogsbom-host-agent || exit 1; \
		mkdir -p bin/package && cp bin/linux-$$a/ogsbom-host-agent bin/package/ogsbom-host-agent || exit 1; \
		for p in deb rpm; do \
			PKG_ARCH=$$a PKG_VERSION=$(PKG_VERSION) $(GO) tool nfpm package --config deploy/nfpm/host-agent.yaml --packager $$p --target dist/ || exit 1; \
		done; \
	done
	@ls -l bin/linux-*/ogsbom-host-agent dist/

.PHONY: run
run: build ## Lance le serveur avec config.yaml
	./bin/ogsbom-server -c config.yaml

.PHONY: fmt
fmt: ## Formate le code
	gofmt -w $$(git ls-files '*.go')

.PHONY: fmt-check
fmt-check: ## Échoue si un fichier n'est pas formaté
	@out=$$(gofmt -l $$(git ls-files '*.go')); if [ -n "$$out" ]; then echo "fichiers non formatés :"; echo "$$out"; exit 1; fi

.PHONY: vet
vet: ## go vet
	$(GO) vet ./...

.PHONY: lint
lint: ## staticcheck
	$(GO) tool staticcheck ./...

.PHONY: vuln
vuln: ## govulncheck
	$(GO) tool govulncheck ./...

.PHONY: generate
generate: ## Régénère le code dérivé (API)
	$(GO) generate ./...

.PHONY: generate-check
generate-check: generate ## Échoue si le code généré n'est pas à jour
	@out=$$(git status --porcelain -- $(GENERATED)); if [ -n "$$out" ]; then echo "code généré obsolète : lancer make generate"; echo "$$out"; exit 1; fi

.PHONY: test
test: ## Tests unitaires
	$(GO) test ./...

.PHONY: test-race
test-race: ## Tests unitaires avec le détecteur de concurrence
	$(GO) test -race ./...

.PHONY: test-integration
test-integration: ## Tests d'intégration (PostgreSQL : docker compose -f deploy/compose.yaml up -d)
	$(GO) test -race -count=1 -tags integration ./...

.PHONY: test-grypedb
test-grypedb: ## Tests avec la vraie base Grype (OGSBOM_TEST_GRYPEDB_DIR : base v6 installée)
	@test -n "$(OGSBOM_TEST_GRYPEDB_DIR)" || { echo "OGSBOM_TEST_GRYPEDB_DIR : répertoire d'une base Grype v6 installée"; exit 1; }
	$(GO) test -count=1 -timeout 30m -tags 'integration grypedb' ./internal/vuln/grype/ ./internal/benchdata/

.PHONY: bench
bench: ## Mesures sur le jeu de référence (docs/benchmarks.md)
	OGSBOM_BENCH=1 $(GO) test -count=1 -timeout 30m -tags integration -run TestReferenceDataset -v ./internal/benchdata/ ./internal/web/

.PHONY: bench-search
bench-search: ## Mesures de la recherche sur le jeu de référence, RLS active (docs/benchmarks.md)
	OGSBOM_BENCH=1 $(GO) test -count=1 -timeout 30m -tags integration -run TestSearchBenchmark -v ./internal/search/

# Autoanalyse : SBOM des binaires par Syft, analyse par Grype, mêmes versions que les
# bibliothèques du projet (go.mod). Grype télécharge sa base, sauf GRYPE_DB_CACHE_DIR et
# GRYPE_DB_AUTO_UPDATE=false.
SYFT  := $(GO) run github.com/anchore/syft/cmd/syft@$(shell $(GO) list -m -f '{{.Version}}' github.com/anchore/syft)
GRYPE := $(GO) run github.com/anchore/grype/cmd/grype@$(shell $(GO) list -m -f '{{.Version}}' github.com/anchore/grype)

.PHONY: sbom
sbom: build ## SBOM CycloneDX des trois binaires (bin/<binaire>.cdx.json)
	@for b in $(BINARIES); do \
		echo "sbom $$b"; \
		$(SYFT) scan file:bin/$$b -q -o cyclonedx-json=bin/$$b.cdx.json || exit 1; \
	done

.PHONY: selfscan
selfscan: sbom ## Analyse les SBOM des binaires ; échec sur une vulnérabilité activement exploitée (KEV)
	@status=0; for b in $(BINARIES); do \
		$(GRYPE) sbom:bin/$$b.cdx.json --by-cve -q -o json --file bin/$$b.grype.json || exit 1; \
		echo "$$b : $$(jq '.matches | length' bin/$$b.grype.json) vulnérabilités, $$(jq '[.matches[] | select((.vulnerability.knownExploited // []) | length > 0)] | length' bin/$$b.grype.json) KEV"; \
		kev=$$(jq -r '.matches[] | select((.vulnerability.knownExploited // []) | length > 0) | "  KEV : \(.vulnerability.id) dans \(.artifact.name) \(.artifact.version)"' bin/$$b.grype.json); \
		if [ -n "$$kev" ]; then echo "$$kev"; status=1; fi; \
	done; exit $$status

.PHONY: ci
ci: fmt-check generate-check vet lint test-race test-integration vuln build packages ## Toutes les vérifications de la CI

.PHONY: clean
clean: ## Supprime les artefacts
	rm -rf bin dist
