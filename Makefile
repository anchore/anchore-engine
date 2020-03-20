# Project Environment Variables
DEV_IMAGE_REPO := anchore/anchore-engine-dev

# Environment variables set in CircleCI environment
export VERBOSE ?= false
export CI ?= false
# DOCKER_USER & DOCKER_PASS are declared in CircleCI contexts
export DOCKER_PASS ?=
export DOCKER_USER ?=
# LATEST_RELEASE_BRANCH is declared in the CircleCI project environment variables settings
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

# Make environment configuration
VENV := venv
PYTHON := $(VENV)/bin/python3
.DEFAULT_GOAL := help # Running `Make` will run the help target
.NOTPARALLEL: # wait for targets to finish

# RUN_TASK is a wrapper script used to invoke commands found in scripts/ci/make/*_tasks
# These scripts are where all individual tasks for the pipeline belong
RUN_TASK := scripts/ci/run_make_task


# Define available make commands -- use ## on target names to create 'help' text

.PHONY: ci ## run full ci pipeline locally
ci: VERBOSE := true
ci: build test push

.PHONY: build
build: Dockerfile ## build dev image
	@$(RUN_TASK) build "$(COMMIT_SHA)" "$(GIT_REPO)" "$(GIT_TAG)" "$(TEST_IMAGE_NAME)"

.PHONY: push push-dev
push: push-dev ## push dev image to dockerhub
push-dev: 
	@$(RUN_TASK) push_dev_image "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(TEST_IMAGE_NAME)"

.PHONY: push-rc
push-rc: 
	@$(RUN_TASK) push_rc_image "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_TAG)"

.PHONY: push-rebuild
push-rebuild: 
	@$(RUN_TASK) push_prod_image_rebuild "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_TAG)"

.PHONY: push-release
push-release: 
	@$(RUN_TASK) push_prod_image_release "$(DEV_IMAGE_REPO)" "$(GIT_BRANCH)" "$(GIT_TAG)"

.PHONY: venv
venv: $(VENV)/bin/activate ## setup virtual environment
$(VENV)/bin/activate:
	@$(RUN_TASK) setup_venv "$(VENV)"

.PHONY: install
install: venv setup.py requirements.txt ## install project to virtual environment
	@$(RUN_TASK) install "$(GIT_REPO)" "$(PYTHON)" "$(VENV)"

.PHONY: install-dev
install-dev: venv setup.py requirements.txt ## install project to virtual environment in editable mode
	@$(RUN_TASK) install_dev "$(GIT_REPO)" "$(PYTHON)" "$(VENV)"

.PHONY: compose-up
compose-up: venv scripts/ci/docker-compose-ci.yaml ## run docker compose with dev image
	@$(RUN_TASK) docker_compose_up "$(TEST_IMAGE_NAME)" "$(VENV)"

.PHONY: compose-down
compose-down: venv scripts/ci/docker-compose-ci.yaml ## stop docker compose
	@$(RUN_TASK) docker_compose_down "$(TEST_IMAGE_NAME)" "$(VENV)"

.PHONY: cluster-up
cluster-up: venv test/e2e/kind-config.yaml ## run kind testing k8s cluster
	@$(RUN_TASK) install_cluster_deps "$(VENV)"
	@$(RUN_TASK) kind_cluster_up "$(VENV)"

.PHONY: cluster-down
cluster-down: venv ## delete kind testing k8s cluster
	@$(RUN_TASK) install_cluster_deps "$(VENV)"
	@$(RUN_TASK) kind_cluster_down "$(VENV)"

.PHONY: lint
lint: venv ## lint code using pylint
	@$(RUN_TASK) lint "$(PYTHON)" "$(VENV)"

.PHONY: test
test: test-unit test-integration test-functional test-e2e ## run all test make recipes -- test-unit, test-integration, test-functional, test-e2e

.PHONY: test-unit
test-unit: venv
	@$(RUN_TASK) unit_tests "$(PYTHON)" "$(VENV)"

.PHONY: test-integration
test-integration: venv
	@$(RUN_TASK) integration_tests "$(PYTHON)" "$(VENV)"

.PHONY: test-functional
test-functional: compose-up
	@$(MAKE) run-test-functional
	@$(MAKE) compose-down

.PHONY: run-test-functional
run-test-functional: venv
	@$(RUN_TASK) functional_tests "$(PYTHON)" "$(VENV)"

.PHONY: test-e2e
test-e2e: setup-test-e2e
	@$(MAKE) run-test-e2e
	@$(MAKE) cluster-down

.PHONY: setup-test-e2e
setup-test-e2e: cluster-up
	@$(RUN_TASK) setup_e2e_tests "$(COMMIT_SHA)" "$(DEV_IMAGE_REPO)" "$(GIT_TAG)" "$(TEST_IMAGE_NAME)" "$(VENV)"

.PHONY: run-test-e2e
run-test-e2e: venv
	@$(RUN_TASK) run_e2e_tests "$(PYTHON)" "$(VENV)"

.PHONY: clean
clean: ## clean up project directory & delete dev image
	@$(RUN_TASK) clean_project_dir "$(TEST_IMAGE_NAME)" "$(VENV)"

.PHONY: printvars
printvars: ## print configured make environment vars
	@$(foreach V,$(sort $(.VARIABLES)),$(if $(filter-out environment% default automatic,$(origin $V)),$(warning $V=$($V) ($(value $V)))))

.PHONY: help
help:
	@$(RUN_TASK) help
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[0;36m%-30s\033[0m %s\n", $$1, $$2}'