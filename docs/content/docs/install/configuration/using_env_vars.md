---
title: "Using Environment Variables in Anchore"
linkTitle: "Environment Variables"
weight: 6
---

Environment variable references may be used in the Anchore config.yaml file to set values that need to be configurable during deployment. 

Using this mechanism a common configuration file can be used with multiple Anchore Engine instances with key values being passed using environment variables.

The config.yaml configuration file is read by the Anchore Engine any references to variables prefixed with ANCHORE will be replaced by the value of the matching environment variable.

For example in the sample configuration file the *host_id* parameter is set be appending the ANCHORE_HOST_ID variable to the string *dockerhostid*

`host_id: 'dockerhostid-${ANCHORE_HOST_ID}'`

Notes:

1. Only variables prefixed with ANCHORE will be replaced
2. If an environment variable is referenced in the configuration file but not set in the environment then a warning will be logged
3. It is recommend to use curly braces, for example ${ANCHORE_PARAM} to avoid potentially ambiguous cases

### Passing Environment Variables as a File

Environment Variables may also be passed as a file contained key value pairs.

```
ANCHORE_HOST_ID=myservice1
ANCHORE_LOG_LEVEL=DEBUG
```

The Anchore Engine will check for an environment variable named *ANCHORE_ENV_FILE* if this variable is set the the Anchore Engine will attempt to read a file at the location specified in this variable.

The Anchore environment file is read before any other Anchore environment variables so any ANCHORE variables passed in the environment will override the values set in the environment file.


