# Occurrence

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**name** | **str** | The name of the occurrence in the form \&quot;projects/{project_id}/occurrences/{occurrence_id}\&quot; @OutputOnly | [optional] 
**resource_url** | **str** | The unique url of the image or container for which the occurrence applies. Example: https://gcr.io/project/image@sha256:foo This field can be used as a filter in list requests. | [optional] 
**note_name** | **str** | An analysis note associated with this image, in the form \&quot;projects/{project_id}/notes/{note_id}\&quot; This field can be used as a filter in list requests. | [optional] 
**kind** | **str** | This explicitly denotes which of the occurrence details is specified. This field can be used as a filter in list requests. @OutputOnly | [optional] 
**custom_details** | [**CustomDetails**](CustomDetails.md) | Details of the custom note. | [optional] 
**vulnerability_details** | [**VulnerabilityDetails**](VulnerabilityDetails.md) | Details of a security vulnerability note. | [optional] 
**build_details** | [**BuildDetails**](BuildDetails.md) | Build details for a verifiable build. | [optional] 
**derived_image** | [**Derived**](Derived.md) | Describes how this resource derives from the basis in the associated note. | [optional] 
**installation** | [**Installation**](Installation.md) | Describes the installation of a package on the linked resource. | [optional] 
**deployment** | [**Deployment**](Deployment.md) | Describes the deployment of an artifact on a runtime. | [optional] 
**discovered** | [**Discovered**](Discovered.md) | Describes the initial scan status for this resource. | [optional] 
**attestation** | [**Attestation**](Attestation.md) | Describes an attestation of an artifact. | [optional] 
**remediation** | **str** | A description of actions that can be taken to remedy the note | [optional] 
**create_time** | **str** | The time this occurrence was created. @OutputOnly | [optional] 
**update_time** | **str** | The time this occurrence was last updated. @OutputOnly | [optional] 
**operation_name** | **str** | The name of the operation that created this note. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


