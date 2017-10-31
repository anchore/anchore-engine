# Note

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**name** | **str** | The name of the note in the form \&quot;projects/{project_id}/notes/{note_id}\&quot; | [optional] 
**short_description** | **str** | A one sentence description of this note | [optional] 
**long_description** | **str** | A detailed description of this note | [optional] 
**kind** | **str** | This explicitly denotes which kind of note is specified. This field can be used as a filter in list requests. @OutputOnly | [optional] 
**vulnerability_type** | [**VulnerabilityType**](VulnerabilityType.md) | A package vulnerability type of note. | [optional] 
**build_type** | [**BuildType**](BuildType.md) | Build provenance type for a verifiable build. | [optional] 
**base_image** | [**Basis**](Basis.md) | A note describing a base image. | [optional] 
**package** | [**Package**](Package.md) | A note describing a package hosted by various package managers. | [optional] 
**deployable** | [**Deployable**](Deployable.md) | A note describing something that can be deployed. | [optional] 
**discovery** | [**Discovery**](Discovery.md) | A note describing a project/analysis type. | [optional] 
**attestation_authority** | [**AttestationAuthority**](AttestationAuthority.md) | A note describing an attestation role. | [optional] 
**related_url** | [**list[RelatedUrl]**](RelatedUrl.md) | Urls associated with this note | [optional] 
**expiration_time** | **str** | Time of expiration for this Note, null if Note currently does not expire. | [optional] 
**create_time** | **str** | The time this note was created. This field can be used as a filter in list requests. @OutputOnly | [optional] 
**update_time** | **str** | The time this note was last updated. This field can be used as a filter in list requests. @OutputOnly | [optional] 
**operation_name** | **str** | The name of the operation that created this note. | [optional] 
**related_note_names** | **list[str]** | Other notes related to this note. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


