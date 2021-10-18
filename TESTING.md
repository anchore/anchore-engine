# How To Run Functional Tests
* In Anchore-engine repo:
	* `sh ./scripts/ci/prep-local-docker-registry-credentials`
	* `make compose-up`
	* `source ./tests/functional/local.env`
	* `pytest tests/functional/...`