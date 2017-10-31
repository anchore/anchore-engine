# BuildDetails

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**provenance** | [**BuildProvenance**](BuildProvenance.md) | The actual provenance | [optional] 
**provenance_bytes** | **str** | Serialized json representation of the provenance, used in generating the BuildSignature in the corresponding Result. After verifying the signature, provenance_bytes can be unmarshalled and compared to the provenance to confirm that it is unchanged. A base64-encoded string representation of the provenance bytes is used for the signature in order to interoperate with openssl which expects this format for signature verification.  The serialized form is captured both to avoid ambiguity in how the provenance is marshalled to json as well to prevent incompatibilities with future changes. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


