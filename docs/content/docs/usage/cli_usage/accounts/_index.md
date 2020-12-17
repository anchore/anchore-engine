---
title: "Accounts and Users"
linkTitle: "User Management"
weight: 7
---

### System Initialization

When the system first initializes it creates a system service account (invisible to users) and a administrator account (admin) with a single administrator user (admin). The password for this user is set at bootstrap using a default value or an override available in the config.yaml on the catalog service (which is what initializes the db). There are two top-level keys in the config.yaml that control this bootstrap:

- *default_admin_password* - To set the initial password (can be updated by using the API once the system is bootstrapped). Defaults to foobar if omitted or unset.

- *default_admin_email* - To set the initial admin account email on bootstrap. Defaults to *admin@myanchore* if unset

### Managing Accounts Using Anchore CLI

These operations must be executed by a user in the *admin* account. These examples are executed from within the *engine-api* container if using the quickstart guide:

First, `exec` into the *engine-api* container, if using the quickstart docker-compose. For other deployment types (eg. helm chart into kubernetes), execute these commands anywhere you have the Anchore CLI installed that can reach the external API endpoint for you deployment.

`docker-compose exec engine-api /bin/bash`

### Getting Account and User Information

```
anchore-cli account whoami
Username: admin
AccountName: admin
AccountEmail: admin@myanchore
AccountType: admin
```

This shows the username and enclosing account of the requester. In this case, the *admin* user of the *admin* account.

### Adding a New Account

```
anchore-cli account add account1 --email account1admin@anchorexample.com
Name: account1
Email: account1admin@anchorexample.com
Type: user
State: enabled
Created: 2018-11-05T23:23:55Z
```

Note that the email address is optional and can be omitted.

At this point the account exists but contains no users. To create a user with a password, see below in the *Managing Users* section.

### Disabling Account

Disabling an account prevents any of that account's users from being able to perform any actions in the system. It also disabled all asynchronous updates on resources in that account, effectively freezing the state of the account and all of its resources. Disabling an account is idempotent, if it is already disabled the operation has no effect. Accounts may be re-enabled after being disabled.

```
anchore-cli account disable account1
Success
```

### Enabling an Account

To restore a disabled account to allow user operations and resource updates, simply enable it. This is idempotent, enabling an already enabled account has no effect.

```
anchore-cli account enable account1
Success
```

### Deleting an Account

**Note:** Deleting an account is irreversible and will delete all of its resources (images, policies, evaluations, etc).

Deleting an account will synchronously delete all users and credentials for the account and transition the account to the deleting state. At this point the system will begin reaping all resources for the account. Once that reaping process is complete, the account record itself is deleted. An account must be in a disabled state prior to deletion. Failure to be in this state results in an error:

```
anchore-cli account del account1
This operation is irreversible. Really delete account account1 along with *all* users and resources associated with this account? (y/N)y
Error: Invalid account state change requested. Cannot go from state enabled to state deleting
HTTP Code: 400

NOTE: accounts must be disabled (anchore-cli account disable <account>) in order to be deleted
```

So, first you must disable the account, as shown above. Once disabled:

```
anchore-cli account del account1
This operation is irreversible. Really delete account account1 along with *all* users and resources associated with this account? (y/N)y
Success

root@1309ecbad8c1:~# anchore-cli account list
Name            Email                                  Type         State           Created                     
admin           admin@myanchore                        admin        enabled         2018-11-03T18:35:42Z        
account1        account1admin@anchorexample.com        user         deleting        2018-11-05T23:23:55Z        
```

### Managing Users Using Anchore CLI

Users exist within accounts, but usernames themselves are globally unique since they are used for authenticating api requests. User management can be performed by any user in the *admin* account in the default Anchore Engine configuration using the native authorizer. For more information on configuring other authorization plugins see: *Authorization Plugins* and *Configuration*.

### Create User in a User-Type Account

```
anchore-cli account user add --account account1 user1 password123
Name: user1
Created: 2018-11-05T23:38:11Z

root@1309ecbad8c1:~# anchore-cli account user list --account account1
Name         Created                     
user1        2018-11-05T23:38:11Z 
```

That user may now use the API:

```
anchore-cli --u user1 --p password123 account whoami
Username: user1
AccountName: account1
AccountEmail: account1admin@anchorexample.com
AccountType: user
```

### Create User in the admin Account (or the account making the request)

```
anchore-cli account user add admin2 password123
Name: admin2
Created: 2018-11-05T23:41:24Z


root@1309ecbad8c1:~# anchore-cli --u admin2 --p password123 account whoami
Username: admin2
AccountName: admin
AccountEmail: admin@myanchore
AccountType: admin
```

### Deleting a User

```
anchore-cli account user del admin2
Success
```

### Updating a User Password

Note that only system admins can execute this for a different user/account.

As an admin, to reset another users credentials:

```
anchore-cli account user setpassword --account account1 --username user1 password456
Password (re)set success
NOTE: Be sure to change the password you're using for this client if you have reset your own password
```

To update your own password:

```
anchore-cli --u user1 --p password456  account user setpassword password123_456
Password (re)set success
NOTE: Be sure to change the password you're using for this client if you have reset your own password

root@1309ecbad8c1:~# anchore-cli --u user1 --p password456  account whoami
Error: Unauthorized
HTTP Code: 401

root@1309ecbad8c1:~# anchore-cli --u user1 --p password123_456  account whoami
Username: user1
AccountName: account1
AccountEmail: account1admin@anchorexample.com
AccountType: user
```