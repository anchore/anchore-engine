############################################################
# Makefile for the Anchore Engine, a service that analyzes
# Docker images and applies user-defined policies for automated
# container image validation and certification. The rules, directives, and variables in this
# Makefile enable testing, Docker image generation, and pushing Docker
# images.
############################################################


# Make environment configuration
#############################################

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help # Running make without args will run the help target
.NOTPARALLEL: # Run make serially

# Dockerhub image repo
DEV_IMAGE_REPO = anchore/anchore-engine-dev

# Shared CI scripts
TEST_HARNESS_REPO = https://github.com/anchore/test-infra.git
CI_CMD = anchore-ci/ci_harness

# Python environment
VENV = .venv
ACTIVATE_VENV := . $(VENV)/bin/activate
PYTHON := $(VENV)/bin/python3

# Testing environment
CI_COMPOSE_FILE = scripts/ci/docker-compose-ci.yaml
CLUSTER_CONFIG = scripts/ci/config/kind-config.yaml
CONTAINER_TEST_CONFIG = scripts/ci/container-tests.yaml
CLUSTER_NAME = anchore-testing
K8S_VERSION = 1.19.0
TEST_IMAGE_NAME = $(GIT_REPO):dev
OS := $(shell uname)

#### CircleCI environment variables
# exported variables are made available to any script called by this Makefile
############################################################

# declared in .circleci/config.yaml
export LATEST_RELEASE_MAJOR_VERSION ?=
export PROD_IMAGE_REPO ?=

# declared in CircleCI contexts
export DOCKER_USER ?=
export DOCKER_PASS ?=

# declared in CircleCI project environment variables settings
export REDHAT_PASS ?=
export REDHAT_REGISTRY ?=

# automatically set to 'true' by CircleCI runners
export CI ?= false

# Use $CIRCLE_BRANCH if it's set, otherwise use current HEAD branch
GIT_BRANCH := $(shell echo $${CIRCLE_BRANCH:=$$(git rev-parse --abbrev-ref HEAD)})

# Use $CIRCLE_PROJECT_REPONAME if it's set, otherwise the git project top level dir name
GIT_REPO := $(shell echo $${CIRCLE_PROJECT_REPONAME:=$$(basename `git rev-parse --show-toplevel`)})

# Use $CIRCLE_SHA if it's set, otherwise use SHA from HEAD
COMMIT_SHA := $(shell echo $${CIRCLE_SHA:=$$(git rev-parse HEAD)})

# Use $CIRCLE_TAG if it's set, otherwise set to null
GIT_TAG := $(shell echo $${CIRCLE_TAG:=null})


#### Make targets
############################################################

.PHONY: ci
ci: lint build test ## Run full CI pipeline, locally

.PHONY: build
build: CLI_REPO ?= git://github.com/anchore/anchore-cli.git
build: Dockerfile setup-test-infra ## Build dev image
	@$(CI_CMD) build "$(COMMIT_SHA)" "$(GIT_TAG)" "$(TEST_IMAGE_NAME)" "$(CLI_REPO)"

.PHONY: install
install: venv setup.py requirements.txt ## Install to virtual environment
	$(ACTIVATE_VENV) && $(PYTHON) setup.py install

.PHONY: install-dev
install-dev: venv setup.py requirements.txt ## Install to virtual environment in editable mode
	$(ACTIVATE_VENV) && $(PYTHON) -m pip install --editable .

.PHONY: lint
lint: venv setup-test-infra ## lint code using pylint
	@$(ACTIVATE_VENV) && $(CI_CMD) lint

.PHONY: clean
clean: ## Clean everything (with prompts)
	@$(CI_CMD) clean "$(VENV)" "$(TEST_IMAGE_NAME)"

.PHONY: clean-all
clean-all: export NOPROMPT = true
clean-all: ## Clean everything (without prompts)
	@$(CI_CMD) clean "$(VENV)" "$(TEST_IMAGE_NAME)" $(NOPROMPT)


# Testing targets
######################

.PHONY: test
test: test-unit test-integration setup-and-test-functional-grype setup-and-test-cli ## Run unit, integration, functional, and end-to-end tests

.PHONY: test-unit
test-unit: export TOX_ENV = py38 ## Run unit tests (tox)
test-unit: venv setup-test-infra
	@$(ACTIVATE_VENV) && $(CI_CMD) test-unit

.PHONY: test-integration
test-integration: export TOX_ENV = py38 ## Engine now requires 3.8
test-integration: venv setup-test-infra ## Run integration tests (tox)
	@$(ACTIVATE_VENV) && $(CI_CMD) test-integration

.PHONY: test-functional
test-functional: venv setup-test-infra ## Run functional tests, assuming compose is running
	@export TEST_IMAGE_NAME="$(TEST_IMAGE_NAME)";\
	if [ "$(OS)" = "Darwin" ]; then \
		export GID_DOCKER=0;\
		export GID_CI=$(shell id -g);\
		docker-compose -f "${CI_COMPOSE_FILE}" build && \
		$(ACTIVATE_VENV) && $(CI_CMD) test-functional "${CI_COMPOSE_FILE}"  ; \
	else \
		export GID_DOCKER=$(shell ls -n /var/run/docker.sock | awk '{ print $$4 }') ;\
		export GID_CI=$(shell id -g) ;\
		docker-compose -f "${CI_COMPOSE_FILE}" build && \
		$(ACTIVATE_VENV) && $(CI_CMD) $(CI_CMD) test-functional "${CI_COMPOSE_FILE}"  ; \
	fi

PHONY: setup-and-test-functional-grype
setup-and-test-functional-grype: venv setup-test-infra ## Stand up/start docker-compose, run functional tests, tear down/stop docker-compose
	@$(ACTIVATE_VENV) && $(CI_CMD) prep-local-docker-registry-credentials
	@$(MAKE) compose-up ANCHORE_VULNERABILITIES_PROVIDER="grype"
	@$(MAKE) test-functional
	@$(MAKE) compose-down

.PHONY: setup-and-test-functional-legacy
setup-and-test-functional-legacy: venv setup-test-infra ## Stand up/start docker-compose, run functional tests, tear down/stop docker-compose
	@$(ACTIVATE_VENV) && $(CI_CMD) prep-local-docker-registry-credentials
	@$(MAKE) compose-up ANCHORE_VULNERABILITIES_PROVIDER="legacy"
	@$(MAKE) test-functional
	@$(MAKE) compose-down

.PHONY: setup-local-testing-cluster
setup-local-testing-cluster: setup-test-infra venv ## Start kind cluster and set up end to end tests
	@$(MAKE) cluster-up
	@$(ACTIVATE_VENV) && $(CI_CMD) setup-local-testing-cluster "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_TAG)" "$(TEST_IMAGE_NAME)" "$(CLUSTER_NAME)"

.PHONY: test-cli
test-cli: setup-test-infra venv ## Run end to end tests (assuming cluster is running and set up has been run)
	@$(ACTIVATE_VENV) && $(CI_CMD) test-cli

.PHONY: setup-and-test-cli
setup-and-test-cli: setup-test-infra venv ## Set up and run end to end tests
	@$(MAKE) setup-local-testing-cluster
	@$(MAKE) test-cli
	@$(MAKE) cluster-down

.PHONY: test-container-dev
test-container-dev: setup-test-infra venv ## CI ONLY Run container-structure-tests on locally built image
	@$(ACTIVATE_VENV) && $(CI_CMD) test-container $(CIRCLE_PROJECT_REPONAME) dev $(CONTAINER_TEST_CONFIG)

.PHONY: test-container-prod
test-container-prod: setup-test-infra venv ## CI ONLY Run container-structure-tests on :latest prod image
	@$(ACTIVATE_VENV) && $(CI_CMD) test-container $(CIRCLE_PROJECT_REPONAME) prod $(CONTAINER_TEST_CONFIG)


# Release targets
#######################

.PHONY: push-nightly
push-nightly: setup-test-infra ## Push nightly Anchore Engine Docker image to Docker Hub
	@$(CI_CMD) push-nightly-image "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(TEST_IMAGE_NAME)"

.PHONY: push-dev
push-dev: setup-test-infra ## Push dev Anchore Engine Docker image to Docker Hub
	@$(CI_CMD) push-dev-image "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(TEST_IMAGE_NAME)"

.PHONY: push-rc
push-rc: setup-test-infra ## Push RC Anchore Engine Docker image to Docker Hub (not available outside of CI)
	@$(CI_CMD) push-rc-image "$(DEV_IMAGE_REPO)" "$(GIT_TAG)" "$(TEST_IMAGE_NAME)"

.PHONY: push-prod
push-prod: setup-test-infra ## Push release Anchore Engine Docker image to Docker Hub (not available outside of CI
	@$(CI_CMD) push-prod-image-release "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(GIT_TAG)"

.PHONY: push-redhat
push-redhat: setup-test-infra ## (Not available outside of CI) Push prod Anchore Engine docker image to RedHat Connect
	@$(CI_CMD) push-redhat-image "$(GIT_TAG)"

.PHONY: push-rebuild
push-rebuild: setup-test-infra ## Rebuild and push prod Anchore Engine docker image to Docker Hub (not available outside of CI)
	@$(CI_CMD) push-prod-image-rebuild "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_TAG)"

ironbank-artifacts: anchore-ci ## (Not available outside of CI) Create and upload ironbank buildblob artifacts
	@$(CI_CMD) create-ironbank-artifacts anchore-engine "$(GIT_TAG)"

# Helper targets
#########################

.PHONY: compose-up
compose-up: venv setup-test-infra ## Stand up/start docker-compose with dev image
	@export TEST_IMAGE_NAME="$(TEST_IMAGE_NAME)";\
	export ANCHORE_VULNERABILITIES_PROVIDER := "legacy" ;\
	if [ "$(OS)" = "Darwin" ]; then \
		export GID_DOCKER=0;\
		export GID_CI=$(shell id -g);\
		docker-compose -f "${CI_COMPOSE_FILE}" build && \
		$(ACTIVATE_VENV) && $(CI_CMD) compose-up "$(TEST_IMAGE_NAME)" "${CI_COMPOSE_FILE}" ; \
	else \
		export GID_DOCKER=$(shell ls -n /var/run/docker.sock | awk '{ print $$4 }') ;\
		export GID_CI=$(shell id -g) ;\
		docker-compose -f "${CI_COMPOSE_FILE}" build && \
		$(ACTIVATE_VENV) && $(CI_CMD) compose-up "$(TEST_IMAGE_NAME)" "${CI_COMPOSE_FILE}" ; \
	fi

.PHONY: compose-down
compose-down: venv setup-test-infra ## Tear down/stop docker compose
	@$(ACTIVATE_VENV) && $(CI_CMD) compose-down "$(TEST_IMAGE_NAME)" "${CI_COMPOSE_FILE}"

.PHONY: cluster-up
cluster-up: venv setup-test-infra ## Set up and run kind cluster
	@$(CI_CMD) install-cluster-deps "$(VENV)"
	@$(ACTIVATE_VENV) && $(CI_CMD) cluster-up "$(CLUSTER_NAME)" "$(CLUSTER_CONFIG)" "$(K8S_VERSION)"

.PHONY: cluster-down
cluster-down: venv setup-test-infra ## Tear down/stop kind cluster
	@$(ACTIVATE_VENV) && $(CI_CMD) cluster-down "$(CLUSTER_NAME)"

.PHONY: setup-test-infra
setup-test-infra: /tmp/test-infra ## Fetch anchore/test-infra repo for CI scripts
	cd /tmp/test-infra && git pull
	@$(MAKE) anchore-ci
anchore-ci: /tmp/test-infra/anchore-ci
	rm -rf ./anchore-ci; cp -R /tmp/test-infra/anchore-ci .
/tmp/test-infra/anchore-ci: /tmp/test-infra
/tmp/test-infra:
	git clone $(TEST_HARNESS_REPO) /tmp/test-infra

.PHONY: venv
venv: $(VENV)/bin/activate ## Set up a virtual environment
$(VENV)/bin/activate:
	python3 -m venv $(VENV)

.PHONY: printvars
printvars: ## Print make variables
	@$(foreach V,$(sort $(.VARIABLES)),$(if $(filter-out environment% default automatic,$(origin $V)),$(warning $V=$($V) ($(value $V)))))

.PHONY: help
help:
	@printf "\n%s\n\n" "usage: make <target>"
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[0;36m%-30s\033[0m %s\n", $$1, $$2}'


# Utility targets
#######################

.PHONY: jq-installed
jq-installed:
ifeq ($(OS),Darwin)
	# Skipping installation of jq for local dev on Mac.
	# You can install via 'brew install jq' the following command if needed.
else
	if ! which jq ; then sudo apt-get install -y jq ; fi
endif

# BSD and GNU cross-platfrom sed -i ''
SEDVERSION = $(shell sed --version >/dev/null 2>&1 ; echo $$? )

ifeq ($(SEDVERSION), 1)
# BSD sed requires a space and does not support --version
SEDI = sed -E -i ''
else
# GNU sed forbids a space and supports --version
SEDI = sed -E -i''
endif


# Code change targets
#######################

SYFT_LATEST_VERSION = $(shell curl "https://api.github.com/repos/anchore/syft/releases/latest" 2>/dev/null | jq -r '.tag_name')
.PHONY: upgrade-syft
upgrade-syft: jq-installed ## Upgrade Syft to the latest release
	if [ -n "$$GITHUB_ENV" ]; then echo "syft_v=${SYFT_LATEST_VERSION}" >> $$GITHUB_ENV; fi
	# Setting Syft to ${SYFT_LATEST_VERSION}
	$(SEDI) 's/^(ENV SYFT_VERSION=).+$$/\1${SYFT_LATEST_VERSION}/' Dockerfile

GRYPE_LATEST_VERSION = $(shell curl "https://api.github.com/repos/anchore/grype/releases/latest" 2>/dev/null | jq -r '.tag_name')
.PHONY: upgrade-grype
upgrade-grype: jq-installed ## Upgrade Grype to the latest release
	if [ -n "$$GITHUB_ENV" ]; then echo "grype_v=${GRYPE_LATEST_VERSION}" >> $$GITHUB_ENV; fi
	# Setting Grype to ${GRYPE_LATEST_VERSION}
	$(SEDI) 's/^(ENV GRYPE_VERSION=).+$$/\1${GRYPE_LATEST_VERSION}/' Dockerfile

# TODO: Intent is to create a weekly/daily/continuous GitHub Action that runs the following and auto-opens a PR
.PHONY: upgrade-anchore-tools
upgrade-anchore-tools: upgrade-syft upgrade-grype ## Upgrade Syft and Grype to the latest release
