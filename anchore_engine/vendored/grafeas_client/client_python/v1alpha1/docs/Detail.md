# Detail

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**cpe_uri** | **str** | The cpe_uri in [cpe format] (https://cpe.mitre.org/specification/) in which the vulnerability manifests.  Examples include distro or storage location for vulnerable jar. This field can be used as a filter in list requests. | [optional] 
**package** | **str** | The name of the package where the vulnerability was found. This field can be used as a filter in list requests. | [optional] 
**min_affected_version** | [**Version**](Version.md) | The min version of the package in which the vulnerability exists. | [optional] 
**max_affected_version** | [**Version**](Version.md) | The max version of the package in which the vulnerability exists. This field can be used as a filter in list requests. | [optional] 
**severity_name** | **str** | The severity (eg: distro assigned severity) for this vulnerability. | [optional] 
**description** | **str** | A vendor-specific description of this note. | [optional] 
**fixed_location** | [**VulnerabilityLocation**](VulnerabilityLocation.md) | The fix for this specific package version. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


