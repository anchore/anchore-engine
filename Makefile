############################################################
# Makefile for the Anchore Engine, a service that analyzes
# Docker images and applies user-defined policies for automated
# container image validation and certification.
############################################################


#### Docker Hub, git repos
############################################################
DEV_IMAGE_REPO := anchore/anchore-engine-dev
#TEST_HARNESS_REPO := https://github.com/anchore/test-infra.git
TEST_HARNESS_REPO := https://github.com/robertp/test-infra.git


#### CircleCI environment variables
############################################################
export VERBOSE ?= false
export CI ?= false
export DOCKER_USER ?=
export DOCKER_PASS ?=
export LATEST_RELEASE_BRANCH ?=
export PROD_IMAGE_REPO ?=
export RELEASE_BRANCHES ?=

# Use $CIRCLE_BRANCH if it's set, otherwise use current HEAD branch
GIT_BRANCH := $(shell echo $${CIRCLE_BRANCH:=$$(git rev-parse --abbrev-ref HEAD)})

# Use $CIRCLE_PROJECT_REPONAME if it's set, otherwise the git project top level dir name
GIT_REPO := $(shell echo $${CIRCLE_PROJECT_REPONAME:=$$(basename `git rev-parse --show-toplevel`)})
TEST_IMAGE_NAME := $(GIT_REPO):dev

# Use $CIRCLE_SHA if it's set, otherwise use SHA from HEAD
COMMIT_SHA := $(shell echo $${CIRCLE_SHA:=$$(git rev-parse HEAD)})

# Use $CIRCLE_TAG if it's set
GIT_TAG ?= $(shell echo $${CIRCLE_TAG:=null})

CLUSTER_NAME := e2e-testing


# Make environment configuration
############################################################
VENV := venv
ACTIVATE_VENV := . $(VENV)/bin/activate
PYTHON := $(VENV)/bin/python3
.DEFAULT_GOAL := help # Running `Make` will run the help target
CLUSTER_CONFIG := tests/e2e/kind-config.yaml
K8S_VERSION := 1.15.7

# Run make serially. Note that recursively invoked make will still
# run recipes in parallel (unless they also contain .NOTPARALLEL)
.NOTPARALLEL:

CI_COMPOSE_FILE := scripts/ci/docker-compose-ci.yaml

CI_CMD := anchore-ci/local_ci


#### Make targets
############################################################

.PHONY: ci build push-dev push-rc push-prod push-rebuild
.PHONY: compose-up compose-down cluster-up cluster-down
.PHONY: test test-unit test-integration
.PHONY: setup-and-test-functional test-functional
.PHONY: setup-test-e2e test-e2e
.PHONY: venv install install-dev lint clean clean-noprompt
.PHONY: printvars help

ci: VERBOSE := true ## run full ci pipeline locally
ci: build test push-dev

anchore-ci: ## Fetch test artifacts for local CI
	rm -rf /tmp/test-infra; git clone $(TEST_HARNESS_REPO) /tmp/test-infra
	mv ./anchore-ci ./anchore-ci-`date +%F-%H-%M-%S`; mv /tmp/test-infra/anchore-ci .

venv: $(VENV)/bin/activate ## Set up a virtual environment
$(VENV)/bin/activate:
	python3 -m venv $(VENV)

build: Dockerfile anchore-ci ## build dev image
	@$(CI_CMD) build "$(COMMIT_SHA)" "$(GIT_TAG)" "$(TEST_IMAGE_NAME)"

push-dev: anchore-ci ## Push dev Anchore Engine Docker image to Docker Hub
	@$(CI_CMD) push-dev-image "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(TEST_IMAGE_NAME)"

push-rc: ## Push RC Anchore Engine Docker image to Docker Hub (not available outside of CI)
	@$(CI_CMD) push-rc-image "$(DEV_IMAGE_REPO)" "$(GIT_TAG)" "$(TEST_IMAGE_NAME)"

push-prod: ## Push release Anchore Engine Docker image to Docker Hub (not available outside of CI
	@$(CI_CMD) push-prod-image-release "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(GIT_TAG)"

push-rebuild: ## Rebuild and push prod Anchore Engine docker image to Docker Hub (not available outside of CI)
	@$(CI_CMD) push-prod-image-rebuild "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_TAG)"

install: venv setup.py requirements.txt ## Install to virtual environment
	@$(ACTIVATE_VENV) && $(PYTHON) setup.py install

install-dev: venv setup.py requirements.txt ## Install to virtual environment in editable mode
	@$(ACTIVATE_VENV) && $(PYTHON) -m pip install --editable .

compose-up: venv anchore-ci ## Stand up/start docker-compose with dev image
	@$(ACTIVATE_VENV) && $(CI_CMD) compose-up "$(TEST_IMAGE_NAME)" "${CI_COMPOSE_FILE}"

compose-down: venv anchore-ci ## Tear down/stop docker compose
	@$(ACTIVATE_VENV) && $(CI_CMD) compose-down "$(TEST_IMAGE_NAME)" "${CI_COMPOSE_FILE}"

install-cluster-deps: anchore-ci venv ## Install kind, helm, and kubectl (unless installed)
	$(CI_CMD) install-cluster-deps "$(VENV)"

cluster-up: anchore-ci venv ## Set up and run kind cluster
	@$(MAKE) install-cluster-deps
	$(ACTIVATE_VENV) && $(CI_CMD) cluster-up "$(CLUSTER_NAME)" "$(CLUSTER_CONFIG)" "$(K8S_VERSION)"

cluster-down: anchore-ci venv ## Tear down/stop kind cluster
	@$(MAKE) install-cluster-deps
	$(ACTIVATE_VENV) && $(CI_CMD) cluster-down "$(CLUSTER_NAME)"

lint: venv anchore-ci ## lint code using pylint
	@$(ACTIVATE_VENV) && $(CI_CMD) lint

test: test-unit test-integration setup-and-test-functional setup-and-test-e2e ## Run all tests

test-unit: venv anchore-ci ## Run unit tests (tox)
	TOX_ENV="py36" $(CI_CMD) test-unit

test-integration: venv anchore-ci ## Run integration tests (tox)
	@$(ACTIVATE_VENV) && $(CI_CMD) test-integration

setup-test-functional: venv anchore-ci ## Stand up/start docker-compose for functional tests
	@$(MAKE) compose-up

test-functional: venv anchore-ci ## Run functional tests, assuming compose is running
	@$(ACTIVATE_VENV) && $(CI_CMD) test-functional

setup-and-test-functional: venv anchore-ci ## Stand up/start docker-compose, run functional tests, tear down/stop docker-compose
	@$(MAKE) compose-up
	@$(MAKE) test-functional
	@$(MAKE) compose-down

setup-test-e2e: anchore-ci venv ## Start kind cluster and set up end to end tests
	@$(MAKE) cluster-up
	@$(ACTIVATE_VENV) && $(CI_CMD) setup-e2e-tests "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_TAG)" "$(TEST_IMAGE_NAME)"

test-e2e: anchore-ci venv ## Run end to end tests (assuming cluster is running and set up has been run)
	@$(ACTIVATE_VENV) && $(CI_CMD) e2e-tests

# Local CI scripts (setup-e2e-tests and e2e-tests)
setup-and-test-e2e: anchore-ci venv ## Set up and run end to end tests
	@$(MAKE) setup-e2e-tests
	@$(MAKE) e2e-tests
	@$(MAKE) cluster-down

clean: ## Clean up project directory and delete dev Docker image
	@$(CI_CMD) clean "$(VENV)" "$(TEST_IMAGE_NAME)"

clean-noprompt: ## Clean up project directory and delete dev Docker image, without asking
	@$(CI_CMD) clean-noprompt "$(VENV)" "$(TEST_IMAGE_NAME)"

printvars: ## Print make variables
	@$(foreach V,$(sort $(.VARIABLES)),$(if $(filter-out environment% default automatic,$(origin $V)),$(warning $V=$($V) ($(value $V)))))

help: ## Show this usage message
	@printf "\n%s\n\n" "usage: make <target>"
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[0;36m%-30s\033[0m %s\n", $$1, $$2}'
