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

.PHONY: run
run: build ## Lance le serveur avec config.yaml
	./bin/ogsbom-server --config config.yaml

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

.PHONY: ci
ci: fmt-check generate-check vet lint test-race test-integration vuln build ## Toutes les vérifications de la CI

.PHONY: clean
clean: ## Supprime les artefacts
	rm -rf bin dist
