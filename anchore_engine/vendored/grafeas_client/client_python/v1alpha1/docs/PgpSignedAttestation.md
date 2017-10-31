# PgpSignedAttestation

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**signature** | **str** | The raw content of the signature, as output by gpg or equivalent.  Since this message only supports attached signatures, the payload that was signed must be attached. While the signature format supported is dependent on the verification implementation, currently only ASCII-armored (&#x60;--armor&#x60; to gpg), non-clearsigned (&#x60;--sign&#x60; rather than &#x60;--clearsign&#x60; to gpg) are supported. Concretely, &#x60;gpg --sign --armor --output&#x3D;signature.gpg payload.json&#x60; will create the signature content expected in this field in &#x60;signature.gpg&#x60; for the &#x60;payload.json&#x60; attestation payload. | [optional] 
**content_type** | **str** | Type (e.g. schema) of the attestation payload that was signed. The verifier must ensure that the provided type is one that the verifier supports, and that the attestation payload is a valid instantiation of that type (e.g. by validating a JSON schema). | [optional] 
**pgp_key_id** | **str** | The ID of the key, as output by &#x60;gpg --list-keys&#x60;.  This should be 8 hexidecimal digits, capitalized.  e.g. $ gpg --list-keys pub 2048R/A663AEEA 2017-08-01 ui Fake Name &lt;example-attesting-user@google.com&gt; In the above example, the &#x60;key_id&#x60; is \&quot;A663AEEA\&quot;. Note that in practice this ID is the last 64 bits of the key fingerprint. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


