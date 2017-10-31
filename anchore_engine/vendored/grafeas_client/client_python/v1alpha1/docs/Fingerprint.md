# Fingerprint

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**v1_name** | **str** | The layer-id of the final layer in the Docker image’s v1 representation. This field can be used as a filter in list requests. | [optional] 
**v2_blob** | **list[str]** | The ordered list of v2 blobs that represent a given image. | [optional] 
**v2_name** | **str** | The name of the image’s v2 blobs computed via:   [bottom] :&#x3D; v2_blobbottom :&#x3D; sha256(v2_blob[N] + “ ” + v2_name[N+1]) Only the name of the final blob is kept. This field can be used as a filter in list requests. @OutputOnly | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


