# Running Anchore Engine Tests
Anchore Engine is covered by automated Unit, Integration, and Functional Tests.
Each type can be run locally using the following steps. 

All require a local checkout of Anchore Engine. Ensure steps are executed from repository root. 

## Running Unit Tests
###Set Up
  * \<Some Set Up Steps>
<br>

###Run Tests 
* From PyCharm:
  * Select 'Run PyTest' for test script to run
* From Terminal:
  * `make test-unit`

## Running Integration Tests

###Set Up
  * \<Some Set Up Steps>
<br>

###Run Tests
* From PyCharm:
  * Select 'Run PyTest' for test script to run
* From Container:
  * `sh setup_deps.sh`
<br>

###Clean Up
* If ran from container
  * `teardown_deps`

## Running Functional Tests
###Set Up
* `source ./tests/functional/local.env`
* `sh ./scripts/ci/prep-local-docker-registry-credentials`
* `make compose-up`
<br>
 
###Run Tests 
* From PyCharm:
  * Select 'Run PyTest' for test script to run
* From Container:
  * `docker exec -it ci_job-runner_1 /bin/bash`
  * `pytest tests/functional/.../some_test.py`
  <br>

###Clean Up
*:q