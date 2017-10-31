# GerritSourceContext

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**host_uri** | **str** | The URI of a running Gerrit instance. | [optional] 
**gerrit_project** | **str** | The full project name within the host. Projects may be nested, so \&quot;project/subproject\&quot; is a valid project name. The \&quot;repo name\&quot; is hostURI/project. | [optional] 
**revision_id** | **str** | A revision (commit) ID. | [optional] 
**alias_name** | **str** | The name of an alias (branch, tag, etc.). | [optional] 
**alias_context** | [**AliasContext**](AliasContext.md) | An alias, which may be a branch or tag. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


