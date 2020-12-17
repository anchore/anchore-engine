---
title: "Configuring User Credential Storage"
linkTitle: "Configuring User Credential Storage"
weight: 4
---

## Overview

When using the Anchore internal DB to manage user identities (external management is optional in the Enterprise version), all user information is stored in
the Anchore DB. The credentials can be stored plaintext in the DB, which allows efficient usage internally for dev/test systems, or the credentials can be
stored in hashed form using the Argon2 hashing algorithm.

Hashed passwords are much more secure, but are expensive to compare and cannot be used for internal service communication since they cannot be reversed. Anchore
provides a token based authentication mechanism as well (a simplified Password-Grant flow of Oauth2) to mitigate the performance issue, but it requires that
all Anchore services be deployed with a shared secret in the configuration or a public/private keypair common to all services.

## Passwords

The configuration of how passwords are stored is set in the `user_authentication` section of the _config.yaml_ file and *must* be consistent across all components of an Anchore Engine deployment. Mismatch
in this configuration between components of the system will result in the system not being able to communicate internally.

```
user_authentication:
  hashed_passwords: true|false
```

By default, `hashed_passwords` is set to `false`. This supports upgrade from previous versions of Anchore as well as usage for installations without a shared key or public/private keys for Anchore. When oauth
is not configured in the system, Anchore must be able to use HTTP Basic authentication between internal services and thus requires credentials that can be read.

## Bearer Tokens/OAuth2

If Anchore is configured to support bearer tokens, the tokens are generated and returned to the user but never persisted in the database. All tokens expire, and currently
Anchore does not support refresh tokens, upon expiration a user must re-authenticate with the username and password to get a new token. Users must still have password credentials, however.
Password persistence and protection configuration still applies as in the Password section above.

## Configuring Hashed Passwords and OAuth

NOTE: password storage configuration must be done at the time of deployment, it cannot be modified at runtime or after installation with an existing DB since
it will invalidate all existing credentials, including internal system credentials and the system will not be functional. You must choose the mechanism
at system deployment time.

Set in _config.yaml_ for all components of the deployment:

Option 1: Use a shared secret for signing/verifying oauth tokens

    user_authentication:
      oauth:
        enabled: true
      hashed_passwords: true
    keys:
      secret: mysecretvalue

Option 2: Use a public/private key pair, delivered as pem files on the filesystem of the containers anchore runs in:

    user_authentication:
      oauth:
        enabled: true
      hashed_passwords: true
    keys:
      private_key_path: <path to private key pem file>
      public_key_path: <path to public key pem file>

Using environment variables with the _config.yaml_ bundled into the Anchore provided anchore-engine image is also an option.
NOTE: These are *only* valid when using the _config.yaml_ provided in the image due to that file referencing them explicitly as replacement values.

    ANCHORE_AUTH_SECRET = the string to use as a secret
    ANCHORE_AUTH_PUBKEY = path to public key file
    ANCHORE_AUTH_PRIVKEY = path to the private key file
    ANCHORE_OAUTH_ENABLED = boolean to enable/disable oauth support
    ANCHORE_OAUTH_TOKEN_EXPIRATION = the integer value to set number of seconds a token should be valid (default is 3600/1 hr)
    ANCHORE_AUTH_ENABLE_HASHED_PASSWORDS = boolean to enable/disable hashed password storage in the anchore db instead of clear text
