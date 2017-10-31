# BuildProvenance

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **str** | Unique identifier of the build. | [optional] 
**project_id** | **str** | ID of the project. | [optional] 
**project_num** | **str** | Numerical ID of the project. | [optional] 
**commands** | [**list[Command]**](Command.md) | Commands requested by the build. | [optional] 
**built_artifacts** | [**list[Artifact]**](Artifact.md) | Output of the build. | [optional] 
**create_time** | **str** | Time at which the build was created. | [optional] 
**start_time** | **str** | Time at which execution of the build was started. | [optional] 
**finish_time** | **str** | Time at whihc execution of the build was finished. | [optional] 
**user_id** | **str** | GAIA ID of end user who initiated this build; at the time that the BuildProvenance is uploaded to Analysis, this will be resolved to the primary e-mail address of the user and stored in the Creator field. | [optional] 
**creator** | **str** | E-mail address of the user who initiated this build. Note that this was the user&#39;s e-mail address at the time the build was initiated; this address may not represent the same end-user for all time. | [optional] 
**logs_bucket** | **str** | Google Cloud Storage bucket where logs were written. | [optional] 
**source_provenance** | [**Source**](Source.md) | Details of the Source input to the build. | [optional] 
**trigger_id** | **str** | Trigger identifier if the build was triggered automatically; empty if not. | [optional] 
**build_options** | **dict(str, str)** | Special options applied to this build. This is a catch-all field where build providers can enter any desired additional details. | [optional] 
**builder_version** | **str** | Version string of the builder at the time this build was executed. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


