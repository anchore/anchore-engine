############################################################
# Makefile for the Anchore Engine, a service that analyzes
# Docker images and applies user-defined policies for automated
# container image validation and certification.
############################################################


#### Docker Hub, git repos
############################################################
DEV_IMAGE_REPO := anchore/anchore-engine-dev
TEST_HARNESS_REPO := https://github.com/robertp/test-infra.git


#### CircleCI environment variables
############################################################
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
VENV := venv
ACTIVATE_VENV := . $(VENV)/bin/activate
PYTHON := $(VENV)/bin/python3
.DEFAULT_GOAL := help # Running `Make` will run the help target

# Run make serially. Note that recursively invoked make will still
# run recipes in parallel (unless they also contain .NOTPARALLEL)
.NOTPARALLEL:

CI_COMPOSE_FILE := scripts/ci/docker-compose-ci.yaml

# RUN_TASK is a wrapper script used to invoke commands found in scripts/ci/make/*_tasks
# These scripts are where all individual tasks for the pipeline belong
RUN_TASK := scripts/ci/run_make_task

CI_CMD := anchore-ci/local_ci

export VERBOSE ?= false


#### Make targets
############################################################

.PHONY: ci build push push-dev push-rc push-prod push-rebuild
.PHONY: test test-unit test-integration test-functional test-e2e
.PHONY: setup-test-e2e run-test-e2e
.PHONY: compose-up compose-down cluster-up cluster-down
.PHONY: venv install install-dev lint clean printvars help

ci: VERBOSE := true ## run full ci pipeline locally
ci: build test push

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

push-rc:
	@$(CI_CMD) push-rc-image "$(DEV_IMAGE_REPO)" "$(GIT_TAG)" "$(TEST_IMAGE_NAME)"

push-prod:
	@$(CI_CMD) push-prod-image-release "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(GIT_TAG)"

push-rebuild:
	@$(CI_CMD) push-prod-image-rebuild "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_TAG)"

install: venv setup.py requirements.txt ## Install to virtual environment
	@$(ACTIVATE_VENV) && $(PYTHON) setup.py install

install-dev: venv setup.py requirements.txt ## Install to virtual environment in editable mode
	@$(ACTIVATE_VENV) && $(PYTHON) -m pip install --editable .

compose-up: venv anchore-ci scripts/ci/docker-compose-ci.yaml ## run docker compose with dev image
	@$(ACTIVATE_VENV) && $(CI_CMD) compose-up "$(TEST_IMAGE_NAME)" "${CI_COMPOSE_FILE}"

compose-down: venv anchore-ci scripts/ci/docker-compose-ci.yaml ## stop docker compose
	@$(ACTIVATE_VENV) && $(CI_CMD) compose-down "$(TEST_IMAGE_NAME)" "${CI_COMPOSE_FILE}"

install-cluster-deps: anchore-ci venv ## Install kind, helm, and kubectl (unless installed)
	$(CI_CMD) install-cluster-deps "$(VENV)"

cluster-up: anchore-ci venv ## Set up and run kind cluster
cluster-up: CLUSTER_CONFIG := tests/e2e/kind-config.yaml
cluster-up: KUBERNETES_VERSION := 1.15.7
cluster-up: tests/e2e/kind-config.yaml
	@$(MAKE) install-cluster-deps
	$(ACTIVATE_VENV) && $(CI_CMD) cluster-up "$(CLUSTER_NAME)" "$(CLUSTER_CONFIG)" "$(KUBERNETES_VERSION)"
	
cluster-down: anchore-ci venv ## Tear down/stop kind cluster
	@$(MAKE) install-cluster-deps
	$(ACTIVATE_VENV) && $(CI_CMD) cluster-down "$(CLUSTER_NAME)"

lint: venv anchore-ci ## lint code using pylint
	@$(ACTIVATE_VENV) && $(CI_CMD) lint

test: test-unit test-integration test-functional test-e2e ## run all test make recipes -- test-unit, test-integration, test-functional, test-e2e

test-unit: venv anchore-ci
	TOX_ENV="py36" $(CI_CMD) test-unit

test-integration: venv anchore-ci
	@$(ACTIVATE_VENV) && $(CI_CMD) test-integration

test-functional: venv anchore-ci ## Run functional tests
	@$(MAKE) compose-up
	@$(ACTIVATE_VENV) && $(CI_CMD) test-functional
	@$(MAKE) compose-down

test-e2e: setup-test-e2e
	@$(MAKE) run-test-e2e
	@$(MAKE) cluster-down

setup-test-e2e: cluster-up
	@$(RUN_TASK) setup_e2e_tests "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_TAG)" "$(TEST_IMAGE_NAME)" "$(VENV)"

run-test-e2e: venv
	@$(RUN_TASK) run_e2e_tests "$(PYTHON)" "$(VENV)"

clean: ## Clean up project directory and delete dev Docker image
	@$(CI_CMD) clean "$(TEST_IMAGE_NAME)"

clean-noprompt: ## Clean up project directory and delete dev Docker image, without asking
	@$(CI_CMD) clean-noprompt "$(TEST_IMAGE_NAME)"

printvars: ## Print make variables
	@$(foreach V,$(sort $(.VARIABLES)),$(if $(filter-out environment% default automatic,$(origin $V)),$(warning $V=$($V) ($(value $V)))))

help: ## Show this usage message
	@printf "\n%s\n\n" "usage: make <target>"
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[0;36m%-30s\033[0m %s\n", $$1, $$2}'
