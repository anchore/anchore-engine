---
title: "Working with Policies"
linkTitle: "Policies"
weight: 3
---

## Overview

Policies are central to the concept of Anchore Engine, this article provides information on how to create, delete, update, and describe policies using the Anchore CLI to interact with a running Anchore Engine deployment. 

At a high-level Anchore Engine consumes policies store in a Policy Bundle that contain:

- Policies
- Whitelists
- Mappings
- Whitelisted Images
- Blacklisted Images

The Anchore Engine can store multiple policy bundles for each user, but only one bundle can be active at any point in time. It is common to store historic bundles to allow previous policies and evaluations to be inspected. The active bundle is the one used for evaluation for notifications, incoming kubernetes webhooks (unless configured otherwise), and other automatic system functions, but a user may request evaluation of any bundle stored in the system using that bundle's id.

For more information on the content and semantics of policy bundles see: Policy Bundles and Evaluation

### Creating Policies

Policy bundles are just JSON documents. Anchore Engine includes a default policy configured at installation that performs basic CVE checks as well as some Dockerfile checks.

To create custom polices, you may:

- Edit JSON manually and upload a file
- Use the Anchore Enterprise UI to edit policies

### Managing Policies

Policies can be managed directly using the REST API or the `anchore-cli policy` command. 

#### Adding Policies from the CLI

The `anchore-cli` tool allows you to upload policy bundles to the Anchore Engine.

`anchore-cli policy add /path/to/policy/bundle.json`

**Note:** Adding a policy bundle will **not** automatically set the bundle to be active, you will need to activate the bundle using the *activate* command. 

#### Listing Policies

The Anchore Engine may store multiple policy bundles however at a given time only one bundle may be active. Policy bundles can be listed using the `policy list` command.

```
$ anchore-cli policy list
Policy ID                                   Active        Created                    Updated                    

715a6056-87ab-49fb-abef-f4b4198c67bf        True          2017-09-02T12:33:28        2017-09-02T12:33:28        

2170857d-b660-4b56-a1a7-06550bf02eb2        False         2017-09-02T12:33:14        2017-09-02T12:33:28   
```

Each policy has a unique ID that will be reference in policy evaluation reports.

**Note:** Times are reported in UTC.

#### Viewing Policies

Using the `policy get` command, summary or detailed information about a policy can be retrieved. The policy is referenced using its unique id.

```
$ policy get 715a6056-87ab-49fb-abef-f4b4198c67bf

Policy ID: 715a6056-87ab-49fb-abef-f4b4198c67bf
Active: True
Created: 2017-09-03T12:33:28
Updated: 2017-09-03T12:33:28
```

The policy bundle can be downloaded in JSON format by passing the `--detail` parameter.

`anchore-cli policy get 715a6056-87ab-49fb-abef-f4b4198c67bf --detail > policybundle.json`

#### Activating Policies

The `policy activate` command can be used to activate a policy bundle. The policy bundle is referenced using its unique id which can be retrieved using the `policy list` command.

`$ anchore-cli policy activate 2170857d-b660-4b56-a1a7-06550bf02eb2`

**Note:** If the Anchore Engine has been configured to automatically synchronize policy bundles from the Anchore Cloud then the active policy may be overridden automatically during the next sync.

#### Deleting Policies

Policies can be deleted from the Anchore Engine using the `policy del` command The policy is referenced using its unique id. A policy marked as *active* cannot be deleted, another policy has to be marked active before deleting the currently active policy.

`$ anchore-cli policy del 715a6056-87ab-49fb-abef-f4b4198c67bf`

#### Describe Policies

The list of available policy items (Gates and Triggers) can be displayed using the policy describe command.

```
$ anchore-cli policy describe

+-----------------+------------------------------------------------------------+
| Gate            | Description                                                |
+-----------------+------------------------------------------------------------+
| always          | Triggers that fire unconditionally if present in policy,   |
|                 | useful for things like testing and blacklisting.           |
+-----------------+------------------------------------------------------------+
| dockerfile      | Checks against the content of a dockerfile if provided, or |
|                 | a guessed dockerfile based on docker layer history if the  |
|                 | dockerfile is not provided.                                |
+-----------------+------------------------------------------------------------+
| files           | Checks against files in the analyzed image including file  |
|                 | content, file names, and filesystem attributes.            |
+-----------------+------------------------------------------------------------+
| licenses        | License checks against found software licenses in the      |
|                 | container image                                            |
+-----------------+------------------------------------------------------------+
| metadata        | Checks against image metadata, such as size, OS, distro,   |
|                 | architecture, etc.                                         |
+-----------------+------------------------------------------------------------+
| npms            | NPM Checks                                                 |
+-----------------+------------------------------------------------------------+
| packages        | Distro package checks                                      |
+-----------------+------------------------------------------------------------+
| passwd_file     | Content checks for /etc/passwd for things like usernames,  |
|                 | group ids, shells, or full entries.                        |
+-----------------+------------------------------------------------------------+
| ruby_gems       | Ruby Gem Checks                                            |
+-----------------+------------------------------------------------------------+
| secret_scans    | Checks for secrets found in the image using configured     |
|                 | regexes found in the "secret_search" section of            |
|                 | analyzer_config.yaml.                                      |
+-----------------+------------------------------------------------------------+
| vulnerabilities | CVE/Vulnerability checks                                   |
+-----------------+------------------------------------------------------------+
```

Without any other parameters the command will output a list of the policy gates.

Each policy gate may include one or more triggers (policy checks). The optional `--gate` parameter is used to request a list of all triggers supported by a gate.

```
$ anchore-cli policy describe --gate=licenses
+-------------------------+----------------------------------------+------------+
| Trigger                 | Description                            | Parameters |
+-------------------------+----------------------------------------+------------+
| blacklist_exact_match   | Triggers if the evaluated image has a  | licenses   |
|                         | package installed with software        |            |
|                         | distributed under the specified (exact |            |
|                         | match) license(s).                     |            |
+-------------------------+----------------------------------------+------------+
| blacklist_partial_match | triggers if the evaluated image has a  | licenses   |
|                         | package installed with software        |            |
|                         | distributed under the specified        |            |
|                         | (substring match) license(s)           |            |
+-------------------------+----------------------------------------+------------+
```

In this example we can see that the licenses gate has two triggers: blacklist_exact_match and blacklist_partial_match.

The optional `--trigger` parameter may be used in conjunction with the `--gate` parameter to return detailed information about specific gates.

```
$ anchore-cli policy describe --gate=licenses --trigger=blacklist_exact_match
+-----------+------------------------------------+----------+----------------------------+
| Parameter | Description                        | Required | Example                    |
+-----------+------------------------------------+----------+----------------------------+
| licenses  | List of license names to blacklist | True     | GPLv2+,GPL-3+,BSD-2-clause |
|           | exactly.                           |          |                            |
+-----------+------------------------------------+----------+----------------------------+
```



