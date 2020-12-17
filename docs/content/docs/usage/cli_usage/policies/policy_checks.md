---
title: "Anchore Policies Checks"
weight: 1
---

## Introduction

Information about the latest available policy gates, triggers and parameters can be retrieved from a running anchore-engine, using the anchore-cli command below:

`# anchore-cli policy describe (--gate <gatename> ( --trigger <triggername))`


## Gates

| Gate            | Description                                                |
|-----------------|------------------------------------------------------------|
| always          | Triggers that fire unconditionally if present in policy, useful for things like testing and blacklisting
| dockerfile      | Checks against the content of a dockerfile if provided, or a guessed dockerfile based on docker layer history if the dockerfile is not provided
| files           | Checks against files in the analyzed image including file  content, file names, and filesystem attributes
| licenses        | License checks against found software licenses in the container image
| malware         | Checks for malware scan findings in the image              
| metadata        | Checks against image metadata, such as size, OS, distro, architecture, etc.
| npms            | NPM Checks
| packages        | Distro package checks
| passwd_file     | Content checks for /etc/passwd for things like usernames, group ids, shells, or full entries
| retrieved_files | Checks against content and/or presence of files retrieved at analysis time from an image
| ruby_gems       | Ruby Gem Checks
| secret_scans    | Checks for secrets and content found in the image using configured regexes found in the "secret_search" section of analyzer_config.yaml
| vulnerabilities | CVE/Vulnerability checks

For a more in-depth list of available gates/triggers, refer to [Anchore Policy Checks]({{< ref "/docs/general/concepts/policy/policy_checks" >}})
