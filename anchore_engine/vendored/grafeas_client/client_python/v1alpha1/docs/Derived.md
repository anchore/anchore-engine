# Derived

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fingerprint** | [**Fingerprint**](Fingerprint.md) | The fingerprint of the derived image | [optional] 
**distance** | **int** | The number of layers by which this image differs from the associated image basis. @OutputOnly | [optional] 
**layer_info** | [**list[Layer]**](Layer.md) | This contains layer-specific metadata, if populated it has length “distance” and is ordered with [distance] being the layer immediately following the base image and [1] being the final layer. | [optional] 
**base_resource_url** | **str** | This contains the base image url for the derived image Occurrence @OutputOnly | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


