# Command

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**name** | **str** | Name of the command, as presented on the command line, or if the command is packaged as a Docker container, as presented to &#x60;docker pull&#x60;. | [optional] 
**env** | **list[str]** | Environment variables set before running this Command. | [optional] 
**args** | **list[str]** | Command-line arguments used when executing this Command. | [optional] 
**dir** | **str** | Working directory (relative to project source root) used when running this Command. | [optional] 
**id** | **str** | Optional unique identifier for this Command, used in wait_for to reference this Command as a dependency. | [optional] 
**wait_for** | **list[str]** | The ID(s) of the Command(s) that this Command depends on. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


