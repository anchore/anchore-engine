# Developing

## Running Functional Tests

There are a couple ways to run functional tests:

1. A docker-compose setup (the same as used in CI)
2. Locally against your own installation

### ...Against docker compose

1. Modify the `tests/functional/local.env` file to meet your needs
1. `source tests/functional/local.env`
1. `make setup-and-test-functional` to standup engine and run the functional tests.

### ...Run locally

1. Modify the `tests/functional/local.env` file to meet your needs
2. `source tests/functional/local.env`
3. `tox tests/functional`