---
title: "Configuring the Anchore CLI"
weight: 1
---

By default the Anchore CLI will try to connect to the Anchore Engine at http://localhost/v1 with no authentication. 

The username, password and URL for the server can be passed to the Anchore CLI using one of three methods:

### Command Line Parameters

The following command line parameters are used to configure the  Anchore CLI to connect to and authenticate with the Anchore Engine.

```
--u   TEXT   Username     eg. admin
--p   TEXT   Password     eg. foobar
--url TEXT   Service URL  eg. http://localhost:8228/v1
--insecure  Skip certificate validation checks (optional)
```

These connection parameters should be passed before any other commands.
eg.

`$ anchore-cli --u admin --p foobar --url http://anchore.example.com:8228/v1`

### Environment Variables

Rather than passing command line parameters for every call to the Anchore CLI they can be stored as environment variables.

```
ANCHORE_CLI_URL=http://myserver.example.com:8228/v1
ANCHORE_CLI_USER=admin
ANCHORE_CLI_PASS=foobar
ANCHORE_CLI_SSL_VERIFY=n
```

### Credentials File (recommended)

The server URL and authentications credentials can be stored in a configuration file stored in the user's home directory. 

The file should be stored in the following location: $HOME/.anchore/credentials.yaml

```
default:
        ANCHORE_CLI_USER: 'admin'
        ANCHORE_CLI_PASS: 'foobar'
        ANCHORE_CLI_URL: 'http://localhost:8228/v1'
```

### Order or Precedence

The Anchore CLi will first look for configuration via command line parameters. If no command line parameters are passed then the environment is checked, finally the CLI will check for a credentials file.

**Note:** All examples in the documentation will presume that the credentials have been configured using either environment variables or the credentials file.
