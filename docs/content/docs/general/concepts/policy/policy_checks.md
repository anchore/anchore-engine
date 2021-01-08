---
title: "Anchore Policy Checks"
linkTitle: "Policy Checks"
weight: 6
---

## Introduction

In this document, we describe the current anchore gates (and related triggers/parameters) that are supported within anchore policy bundles.  If you have a running anchore engine, this information can also be obtained using the CLI:

`# anchore-cli policy describe (--gate <gatename> ( --trigger <triggername))`

### Gate: dockerfile

Checks against the content of a dockerfile if provided, or a guessed dockerfile based on docker layer history if the dockerfile is not provided.

| Trigger Name | Description | Parameter | Description | Example |
| :----------- | :---------- | :-------- | :---------- | :------ |
| instruction | Triggers if any directives in the list are found to match the described condition in the dockerfile. | instruction | The Dockerfile instruction to check. | from |
| instruction | Triggers if any directives in the list are found to match the described condition in the dockerfile. | check | The type of check to perform. | = |
| instruction | Triggers if any directives in the list are found to match the described condition in the dockerfile. | value | The value to check the dockerfile instruction against. | scratch |
| instruction | Triggers if any directives in the list are found to match the described condition in the dockerfile. | actual_dockerfile_only | Only evaluate against a user-provided dockerfile, skip evaluation on inferred/guessed dockerfiles. Default is False. | true |
| effective_user | Checks if the effective user matches the provided user names, either as a whitelist or blacklist depending on the type parameter setting. | users | User names to check against as the effective user (last user entry) in the images history. | root,docker |
| effective_user | Checks if the effective user matches the provided user names, either as a whitelist or blacklist depending on the type parameter setting. | type | How to treat the provided user names. | blacklist |
| exposed_ports | Evaluates the set of ports exposed. Allows configuring whitelist or blacklist behavior. If type=whitelist, then any ports found exposed that are not in the list will cause the trigger to fire. If type=blacklist, then any ports exposed that are in the list will cause the trigger to fire. | ports | List of port numbers. | 80,8080,8088 |
| exposed_ports | Evaluates the set of ports exposed. Allows configuring whitelist or blacklist behavior. If type=whitelist, then any ports found exposed that are not in the list will cause the trigger to fire. If type=blacklist, then any ports exposed that are in the list will cause the trigger to fire. | type | Whether to use port list as a whitelist or blacklist. | blacklist |
| exposed_ports | Evaluates the set of ports exposed. Allows configuring whitelist or blacklist behavior. If type=whitelist, then any ports found exposed that are not in the list will cause the trigger to fire. If type=blacklist, then any ports exposed that are in the list will cause the trigger to fire. | actual_dockerfile_only | Only evaluate against a user-provided dockerfile, skip evaluation on inferred/guessed dockerfiles. Default is False. | true |
| no_dockerfile_provided | Triggers if anchore analysis was performed without supplying the actual image Dockerfile. | | | |

### Gate: files

Checks against files in the analyzed image including file content, file names, and filesystem attributes.

| Trigger Name | Description | Parameter | Description | Example |
| :----------- | :---------- | :-------- | :---------- | :------ |
| content_regex_match | Triggers for each file where the content search analyzer has found a match using configured regexes in the analyzer_config.yaml "content_search" section. If the parameter is set, the trigger will only fire for files that matched the named regex. Refer to your analyzer_config.yaml for the regex values. | regex_name | Regex string that also appears in the FILECHECK_CONTENTMATCH analyzer parameter in analyzer configuration, to limit the check to. If set, will only fire trigger when the specific named regex was found in a file. | .*password.* |
| name_match | Triggers if a file exists in the container that has a filename that matches the provided regex. This does have a performance impact on policy evaluation. | regex | Regex to apply to file names for match. | .*\.pem |
| attribute_match | Triggers if a filename exists in the container that has attributes that match those which are provided . This check has a performance impact on policy evaluation. | filename | Filename to check against provided checksum. | /etc/passwd |
| attribute_match | Triggers if a filename exists in the container that has attributes that match those which are provided . This check has a performance impact on policy evaluation. | checksum_algorithm | Checksum algorithm | sha256 |
| attribute_match | Triggers if a filename exists in the container that has attributes that match those which are provided . This check has a performance impact on policy evaluation. | checksum | Checksum of file. | 832cd0f75b227d13aac82b1f70b7f90191a4186c151f9db50851d209c45ede11 |
| attribute_match | Triggers if a filename exists in the container that has attributes that match those which are provided . This check has a performance impact on policy evaluation. | checksum_match | Checksum operation to perform. | equals |
| attribute_match | Triggers if a filename exists in the container that has attributes that match those which are provided . This check has a performance impact on policy evaluation. | mode | File mode of file. | 00644 |
| attribute_match | Triggers if a filename exists in the container that has attributes that match those which are provided . This check has a performance impact on policy evaluation. | mode_op | File mode operation to perform. | equals |
| attribute_match | Triggers if a filename exists in the container that has attributes that match those which are provided . This check has a performance impact on policy evaluation. | skip_missing | If set to true, do not fire this trigger if the file is not present.  If set to false, fire this trigger ignoring the other parameter settings. | true |
| suid_or_guid_set | Fires for each file found to have suid or sgid bit set. | | | |

### Gate: passwd_file

Content checks for /etc/passwd for things like usernames, group ids, shells, or full entries.

| Trigger Name | Description | Parameter | Description | Example |
| :----------- | :---------- | :-------- | :---------- | :------ |
| content_not_available | Triggers if the /etc/passwd file is not present/stored in the evaluated image. | | | |
| blacklist_usernames | Triggers if specified username is found in the /etc/passwd file | user_names | List of usernames that will cause the trigger to fire if found in /etc/passwd. | daemon,ftp |
| blacklist_userids | Triggers if specified user id is found in the /etc/passwd file | user_ids | List of userids (numeric) that will cause the trigger to fire if found in /etc/passwd. | 0,1 |
| blacklist_groupids | Triggers if specified group id is found in the /etc/passwd file | group_ids | List of groupids (numeric) that will cause the trigger ot fire if found in /etc/passwd. | 999,20 |
| blacklist_shells | Triggers if specified login shell for any user is found in the /etc/passwd file | shells | List of shell commands to blacklist. | /bin/bash,/bin/zsh |
| blacklist_full_entry | Triggers if entire specified passwd entry is found in the /etc/passwd file. | entry | Full entry to match in /etc/passwd. | ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin |

### Gate: packages

Distro package checks

| Trigger Name | Description | Parameter | Description | Example |
| :----------- | :---------- | :-------- | :---------- | :------ |
| required_package | Triggers if the specified package and optionally a specific version is not found in the image. | name | Name of package that must be found installed in image. | libssl |
| required_package | Triggers if the specified package and optionally a specific version is not found in the image. | version | Optional version of package for exact version match. | 1.10.3rc3 |
| required_package | Triggers if the specified package and optionally a specific version is not found in the image. | version_match_type | The type of comparison to use for version if a version is provided. | exact |
| verify | Check package integrity against package db in the image. Triggers for changes or removal or content in all or the selected "dirs" parameter if provided, and can filter type of check with the "check_only" parameter. | only_packages | List of package names to limit verification. | libssl,openssl |
| verify | Check package integrity against package db in the image. Triggers for changes or removal or content in all or the selected "dirs" parameter if provided, and can filter type of check with the "check_only" parameter. | only_directories | List of directories to limit checks so as to avoid checks on all dir. | /usr,/var/lib |
| verify | Check package integrity against package db in the image. Triggers for changes or removal or content in all or the selected "dirs" parameter if provided, and can filter type of check with the "check_only" parameter. | check | Check to perform instead of all. | changed |
| blacklist | Triggers if the evaluated image has a package installed that matches the named package optionally with a specific version as well. | name | Package name to blacklist. | openssh-server |
| blacklist | Triggers if the evaluated image has a package installed that matches the named package optionally with a specific version as well. | version | Specific version of package to blacklist. | 1.0.1 |

### Gate: vulnerabilities

CVE/Vulnerability checks.

| Trigger Name | Description | Parameter | Description | Example |
| :----------- | :---------- | :-------- | :---------- | :------ |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | package_type | Only trigger for specific package type. | all |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | severity_comparison | The type of comparison to perform for severity evaluation. | > |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | severity | Severity to compare against. | high |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | cvss_v3_base_score_comparison | The type of comparison to perform for CVSS v3 base score evaluation. | > |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | cvss_v3_base_score | CVSS v3 base score to compare against. | None |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | cvss_v3_exploitability_score_comparison | The type of comparison to perform for CVSS v3 exploitability sub score evaluation. | > |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | cvss_v3_exploitability_score | CVSS v3 exploitability sub score to compare against. | None |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | cvss_v3_impact_score_comparison | The type of comparison to perform for CVSS v3 impact sub score evaluation. | > |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | cvss_v3_impact_score | CVSS v3 impact sub score to compare against. | None |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | fix_available | If present, the fix availability for the vulnerability record must match the value of this parameter. | true |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | vendor_only | If True, an available fix for this CVE must not be explicitly marked as wont be addressed by the vendor | true |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | max_days_since_creation | If provided, this CVE must be older than the days provided to trigger. | 7 |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | max_days_since_fix | If provided (only evaluated when fix_available option is also set to true), the fix first observed time must be older than days provided, to trigger. | 30 |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | vendor_cvss_v3_base_score_comparison | The type of comparison to perform for vendor specified CVSS v3 base score evaluation. | > |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | vendor_cvss_v3_base_score | Vendor CVSS v3 base score to compare against. | None |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | vendor_cvss_v3_exploitability_score_comparison | The type of comparison to perform for vendor specified CVSS v3 exploitability sub score evaluation. | > |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | vendor_cvss_v3_exploitability_score | Vendor CVSS v3 exploitability sub score to compare against. | None |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | vendor_cvss_v3_impact_score_comparison | The type of comparison to perform for vendor specified CVSS v3 impact sub score evaluation. | > |
| package | Triggers if a found vulnerability in an image meets the comparison criteria. | vendor_cvss_v3_impact_score | Vendor CVSS v3 impact sub score to compare against. | None |
| blacklist | Triggers if any of a list of specified vulnerabilities has been detected in the image. | vulnerability_ids | List of vulnerability IDs, will cause the trigger to fire if any are detected. | CVE-2019-1234 |
| blacklist | Triggers if any of a list of specified vulnerabilities has been detected in the image. | vulnerability_ids | If set to True, discard matches against this vulnerability if vendor has marked as will not fix in the vulnerability record. | True | 
| stale_feed_data | Triggers if the CVE data is older than the window specified by the parameter MAXAGE (unit is number of days). | max_days_since_sync | Fire the trigger if the last sync was more than this number of days ago. | 10 |
| vulnerability_data_unavailable | Triggers if vulnerability data is unavailable for the image's distro. | | | |

### Gate: licenses

License checks against found software licenses in the container image

| Trigger Name | Description | Parameter | Description | Example |
| :----------- | :---------- | :-------- | :---------- | :------ |
| blacklist_exact_match | Triggers if the evaluated image has a package installed with software distributed under the specified (exact match) license(s). | licenses | List of license names to blacklist exactly. | GPLv2+,GPL-3+,BSD-2-clause |
| blacklist_partial_match | triggers if the evaluated image has a package installed with software distributed under the specified (substring match) license(s) | licenses | List of strings to do substring match for blacklist. | LGPL,BSD |

### Gate: ruby_gems

Ruby Gem Checks

| Trigger Name | Description | Parameter | Description | Example |
| :----------- | :---------- | :-------- | :---------- | :------ |
| newer_version_found_in_feed | Triggers if an installed GEM is not the latest version according to GEM data feed. | | | |
| not_found_in_feed | Triggers if an installed GEM is not in the official GEM database, according to GEM data feed. | | | |
| version_not_found_in_feed | Triggers if an installed GEM version is not listed in the official GEM feed as a valid version. | | | |
| blacklist | Triggers if the evaluated image has a GEM package installed that matches the specified name and version. | name | Gem name to blacklist. | time_diff |
| blacklist | Triggers if the evaluated image has a GEM package installed that matches the specified name and version. | version | Optional version to blacklist specifically. | 0.2.9 |
| feed_data_unavailable | Triggers if anchore does not have access to the GEM data feed. | | | |

### Gate: npms

NPM Checks

| Trigger Name | Description | Parameter | Description | Example |
| :----------- | :---------- | :-------- | :---------- | :------ |
| newer_version_in_feed | Triggers if an installed NPM is not the latest version according to NPM data feed. | | | |
| unknown_in_feeds | Triggers if an installed NPM is not in the official NPM database, according to NPM data feed. | | | |
| version_not_in_feeds | Triggers if an installed NPM version is not listed in the official NPM feed as a valid version. | | | |
| blacklisted_name_version | Triggers if the evaluated image has an NPM package installed that matches the name and optionally a version specified in the parameters. | name | Npm package name to blacklist. | time_diff |
| blacklisted_name_version | Triggers if the evaluated image has an NPM package installed that matches the name and optionally a version specified in the parameters. | version | Npm package version to blacklist specifically. | 0.2.9 |
| feed_data_unavailable | Triggers if the engine does not have access to the NPM data feed. | | | |

### Gate: secret_scans

Checks for secrets and content found in the image using configured regexes found in the "secret_search" section of analyzer_config.yaml.

| Trigger Name | Description | Parameter | Description | Example |
| :----------- | :---------- | :-------- | :---------- | :------ |
| content_regex_checks | Triggers if the secret content search analyzer has found any matches with the configured and named regexes. Checks can be configured to trigger if a match is found or is not found (selected using match_type parameter).  Matches are filtered by the content_regex_name and filename_regex if they are set. The content_regex_name shoud be a value from the "secret_search" section of the analyzer_config.yaml. | content_regex_name | Name of content regexps configured in the analyzer that match if found in the image, instead of matching all. Names available by default are: ['AWS_ACCESS_KEY', 'AWS_SECRET_KEY', 'PRIV_KEY', 'DOCKER_AUTH', 'API_KEY']. | AWS_ACCESS_KEY |
| content_regex_checks | Triggers if the secret content search analyzer has found any matches with the configured and named regexes. Checks can be configured to trigger if a match is found or is not found (selected using match_type parameter).  Matches are filtered by the content_regex_name and filename_regex if they are set. The content_regex_name shoud be a value from the "secret_search" section of the analyzer_config.yaml. | filename_regex | Regexp to filter the content matched files by. | /etc/.* |
| content_regex_checks | Triggers if the secret content search analyzer has found any matches with the configured and named regexes. Checks can be configured to trigger if a match is found or is not found (selected using match_type parameter).  Matches are filtered by the content_regex_name and filename_regex if they are set. The content_regex_name shoud be a value from the "secret_search" section of the analyzer_config.yaml. | match_type | Set to define the type of match - trigger if match is found (default) or not found. | found |

### Gate: metadata

Checks against image metadata, such as size, OS, distro, architecture, etc.

| Trigger Name | Description | Parameter | Description | Example |
| :----------- | :---------- | :-------- | :---------- | :------ |
| attribute | Triggers if a named image metadata value matches the given condition. | attribute | Attribute name to be checked. | size |
| attribute | Triggers if a named image metadata value matches the given condition. | check | The operation to perform the evaluation. | > |
| attribute | Triggers if a named image metadata value matches the given condition. | value | Value used in comparison. | 1073741824 |

### Gate: always

Triggers that fire unconditionally if present in policy, useful for things like testing and blacklisting.

| Trigger Name | Description | Parameter | Description | Example |
| :----------- | :---------- | :-------- | :---------- | :------ |
| always | Fires if present in a policy being evaluated. Useful for things like blacklisting images or testing mappings and whitelists by using this trigger in combination with policy mapping rules. | | | |

### Gate: retrieved_files

Checks against content and/or presence of files retrieved at analysis time from an image

| Trigger Name | Description | Parameter | Description | Example |
| :----------- | :---------- | :-------- | :---------- | :------ |
| content_not_available | Triggers if the specified file is not present/stored in the evaluated image. | path | The path of the file to verify has been retrieved during analysis | /etc/httpd.conf |
| content_regex | Evaluation of regex on retrieved file content | path | The path of the file to verify has been retrieved during analysis | /etc/httpd.conf |
| content_regex | Evaluation of regex on retrieved file content | check | The type of check to perform with the regex | match |
| content_regex | Evaluation of regex on retrieved file content | regex | The regex to evaluate against the content of the file | .*SSlEnabled.* |

### Gate: Malware

| Trigger | Description                        | Parameters |
|---------|------------------------------------|------------|
| scans   | Triggers if any malware scanner has found any matches in the image.  |  |
| scan_not_run | Triggers if no scan was found for the image. | | 


### Next Steps

Now that you have a good grasp on the core concepts and architecture, check out the [Requirements]({{< ref "/docs/install/requirements" >}}) section for running Anchore. 
