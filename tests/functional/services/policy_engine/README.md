# Policy Engine Functional Tests

There are a number of new patterns that were introduced with the new functional tests added for the policy engine prior to the switch from engine to grype for vulnerability matching. These changes and procedures for updating the seeded data for the tests can be found in this document.

# Infrastructure
There are a couple of infrastructural requirements to run these tests outside of the ci. The catalog and policy engine services are not exposed by default, but the tests need to be able to query these services directly in order to work. The ci can use internal service urls, but when running locally your set up might not be able to do this. If this is the case, `tests/functional/local.env` has a set of env variables that the tests can use to override the default ci urls:
```
export ANCHORE_CATALOG_URL=http://localhost:8330/v1  
export ANCHORE_POLICY_ENGINE_URL=http://localhost:8331/v1  
export ANCHORE_TEST_DB_URL=postgresql://postgres:mysecretpassword@localhost:5432/postgres
```

To support these env variables, each service needs to be exposed on the specified port and the psql credentials need to match on the instance of anchore that is running. 

There are some additional infrastructure requirements for the feed tests to work that can be seen [here](#Feeds-Data-Tests)


# Vulnerability Data Tests

These contain a variety of tests that validate various endpoints in how the policy engine handles vulnerability scanning and vulnerability data

## Adding images to policy engine directly

Most of the vulnerability tests require an image to be added directly to the policy engine. Given these are functional tests, the analyzer needs to be bypassed. The first step in adding a new image is to satisfy the requirement that an analysis file of the image already be present within object storage at the correct path. The best way to do this is spin up an instance of anchore engine and add the image for analysis using the cli. Once the analysis is complete, you can pull the analysis file directly from the object storage using the api. The results of this call need to be added to the analysis file directory which can all be done by using the following command at the root of the project directory, swapping out the image digests with the one you are adding and the name of the image you are adding as the name of the file:

```
curl -u admin:foobar http://localhost:8228/v1/objects/analysis_data/<image_digest> > tests/functional/services/policy_engine/vulnerability_data_tests/analysis_files/<image_name>.json
```

In order to add the image for use in the tests, an instance of `AnalysisFile` needs to be added to `ANALYSIS_FILES` in the vulnerability_data_tests conftest, where the first param is the name of the file added to the analysis_files directory by the above command, and the second param is the digest of the image. 

With that in place, the image will ingress into the policy engine for use within these tests by utilizing fixtures that use the `ANALYSIS_FILES` variable.

## Adding Vulnerability Data
These tests also use a static set of vulnerability data to verify the endpoints and analysis are working properly. The seed files can be found in `tests/functional/services/policy_engine/vulnerability_data_tests/database_seed_files`, where each file is named after the table that its data will be added to. Additionally these file names are used to dynamically determine which tables need to be dropped both before and after the tests have run. 

Adding data to an existing file is as simple as appending to the existing json files for that able. In the event that you want to add new tables, first create a json file that is named after the database table you are adding. Then just add an entry into `SEED_FILE_TO_DB_TABLE_MAP` in the vulnerability_data_tests conftest file where the key is the name of the file and the value is the class that it maps to.

When determining what vulnerabilities to seed to the db for our vulnerability scanning tests, we added the image to anchore for analysis throiugh the cli of a running instance of anchore that was spun up with preload db (specifically anchore/engine-db-preload@sha256:810fcdc1fc831b9fdda5d8999fd845808f2f370ff746c712e8f9e330d4703a06). We pulled the cves and cpes from the vuln report of that image and then pulled the data from the db using the following queries as an example: 
```
copy (select row_to_json(t) from (SELECT * FROM feed_data_vulnerabilities WHERE id IN (<vuln_ids>)) t) to '/psql_json/feed_data_vulnerabilities.json';

copy (select row_to_json(t) from (SELECT * FROM feed_data_vulnerabilities_fixed_artifacts WHERE vulnerability_id IN (<vuln_ids>)) t) to '/psql_json/feed_data_vulnerabilities_fixed_artifacts.json';

copy (select row_to_json(t) from ( SELECT * from feed_data_nvdv2_vulnerabilities WHERE name IN (<vuln_ids>)) t) to '/psql_json/feed_data_nvdv2_vulnerabilities.json';

copy (select row_to_json(t) from ( SELECT * from feed_data_cpev2_vulnerabilities WHERE vulnerability_id IN (<vuln_ids>)) t) to '/psql_json/feed_data_cpev2_vulnerabilities.json';
```


# Feeds Data Tests
This folder tests how the policy engine handles feeds. Currently there is only one that verifies the feeds sync work as expected by using an nginx container defined in `docker-compose-ci.yaml` that mimics ancho.re feeds. In order to work, the policy engine service has to have a couple of env variables set. 
```
- ANCHORE_FEEDS_URL="http://mock-feeds-nginx:8080/v1/service/feeds"  
- ANCHORE_FEEDS_ENABLED=true  
- ANCHORE_FEEDS_CLIENT_URL=null  
- ANCHORE_FEEDS_TOKEN_URL=null
 ```
 
## Adding New Feed Data
Feed data can be found at `tests/functional/services/policy_engine/feeds_data_tests/expected_content/test_feed_sync/data`. The structure here allows for querying the nginx container as if it was the ancho.re feed service. Under the feeds folder there is a folder for each feed being tested. There is also an index.json file that mimics the response from `GET v1/services/feeds`. Within each feeds folder there is a json file that contains the vulnerabilities for each group within that feed. There is also an index.json file that mimics `GET v1/services/feeds/<feed_name>`.

If adding data to an existing group, all that is necessary is to simply append the records to the data array in its file. However, additional work is required if adding new feeds/groups. The tests dynamically read the index files to determine what data need to be asserted. This means that you must update the feeds index.json for any feeds added and the feed's index.json for any groups added. 


