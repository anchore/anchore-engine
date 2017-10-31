# swagger_client.GrafeasApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_note**](GrafeasApi.md#create_note) | **POST** /v1alpha1/projects/{projectsId}/notes | 
[**create_occurrence**](GrafeasApi.md#create_occurrence) | **POST** /v1alpha1/projects/{projectsId}/occurrences | 
[**delete_note**](GrafeasApi.md#delete_note) | **DELETE** /v1alpha1/projects/{projectsId}/notes/{notesId} | 
[**delete_occurrence**](GrafeasApi.md#delete_occurrence) | **DELETE** /v1alpha1/projects/{projectsId}/occurrences/{occurrencesId} | 
[**get_note**](GrafeasApi.md#get_note) | **GET** /v1alpha1/projects/{projectsId}/notes/{notesId} | 
[**get_occurrence**](GrafeasApi.md#get_occurrence) | **GET** /v1alpha1/projects/{projectsId}/occurrences/{occurrencesId} | 
[**get_occurrence_note**](GrafeasApi.md#get_occurrence_note) | **GET** /v1alpha1/projects/{projectsId}/occurrences/{occurrencesId}/notes | 
[**get_operation**](GrafeasApi.md#get_operation) | **GET** /v1alpha1/projects/{projectsId}/operations/{operationsId} | 
[**list_note_occurrences**](GrafeasApi.md#list_note_occurrences) | **GET** /v1alpha1/projects/{projectsId}/notes/{notesId}/occurrences | 
[**list_notes**](GrafeasApi.md#list_notes) | **GET** /v1alpha1/projects/{projectsId}/notes | 
[**list_occurrences**](GrafeasApi.md#list_occurrences) | **GET** /v1alpha1/projects/{projectsId}/occurrences | 
[**list_operations**](GrafeasApi.md#list_operations) | **GET** /v1alpha1/projects/{projectsId}/operations | 
[**update_note**](GrafeasApi.md#update_note) | **PUT** /v1alpha1/projects/{projectsId}/notes/{notesId} | 
[**update_occurrence**](GrafeasApi.md#update_occurrence) | **PUT** /v1alpha1/projects/{projectsId}/occurrences/{occurrencesId} | 
[**update_operation**](GrafeasApi.md#update_operation) | **PUT** /v1alpha1/projects/{projectsId}/operations/{operationsId} | 


# **create_note**
> Note create_note(projects_id, note_id=note_id, note=note)



Creates a new note.

### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.GrafeasApi()
projects_id = 'projects_id_example' # str | Part of `parent`. This field contains the projectId for example: \"project/{project_id}
note_id = 'note_id_example' # str | The ID to use for this note. (optional)
note = swagger_client.Note() # Note | The Note to be inserted (optional)

try: 
    api_response = api_instance.create_note(projects_id, note_id=note_id, note=note)
    pprint(api_response)
except ApiException as e:
    print "Exception when calling GrafeasApi->create_note: %s\n" % e
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **projects_id** | **str**| Part of &#x60;parent&#x60;. This field contains the projectId for example: \&quot;project/{project_id} | 
 **note_id** | **str**| The ID to use for this note. | [optional] 
 **note** | [**Note**](Note.md)| The Note to be inserted | [optional] 

### Return type

[**Note**](Note.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **create_occurrence**
> Occurrence create_occurrence(projects_id, occurrence=occurrence)



Creates a new occurrence.

### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.GrafeasApi()
projects_id = 'projects_id_example' # str | Part of `parent`. This field contains the projectId for example: \"projects/{project_id}\"
occurrence = swagger_client.Occurrence() # Occurrence | The occurrence to be inserted (optional)

try: 
    api_response = api_instance.create_occurrence(projects_id, occurrence=occurrence)
    pprint(api_response)
except ApiException as e:
    print "Exception when calling GrafeasApi->create_occurrence: %s\n" % e
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **projects_id** | **str**| Part of &#x60;parent&#x60;. This field contains the projectId for example: \&quot;projects/{project_id}\&quot; | 
 **occurrence** | [**Occurrence**](Occurrence.md)| The occurrence to be inserted | [optional] 

### Return type

[**Occurrence**](Occurrence.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **delete_note**
> Empty delete_note(projects_id, notes_id)



Deletes the given note from the system.

### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.GrafeasApi()
projects_id = 'projects_id_example' # str | Part of `name`. The name of the note in the form \"projects/{project_id}/notes/{note_id}\"
notes_id = 'notes_id_example' # str | Part of `name`. See documentation of `projectsId`.

try: 
    api_response = api_instance.delete_note(projects_id, notes_id)
    pprint(api_response)
except ApiException as e:
    print "Exception when calling GrafeasApi->delete_note: %s\n" % e
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **projects_id** | **str**| Part of &#x60;name&#x60;. The name of the note in the form \&quot;projects/{project_id}/notes/{note_id}\&quot; | 
 **notes_id** | **str**| Part of &#x60;name&#x60;. See documentation of &#x60;projectsId&#x60;. | 

### Return type

[**Empty**](Empty.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **delete_occurrence**
> Empty delete_occurrence(projects_id, occurrences_id)



Deletes the given occurrence from the system.

### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.GrafeasApi()
projects_id = 'projects_id_example' # str | Part of `name`. The name of the occurrence in the form \"projects/{project_id}/occurrences/{occurrence_id}\"
occurrences_id = 'occurrences_id_example' # str | Part of `name`. See documentation of `projectsId`.

try: 
    api_response = api_instance.delete_occurrence(projects_id, occurrences_id)
    pprint(api_response)
except ApiException as e:
    print "Exception when calling GrafeasApi->delete_occurrence: %s\n" % e
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **projects_id** | **str**| Part of &#x60;name&#x60;. The name of the occurrence in the form \&quot;projects/{project_id}/occurrences/{occurrence_id}\&quot; | 
 **occurrences_id** | **str**| Part of &#x60;name&#x60;. See documentation of &#x60;projectsId&#x60;. | 

### Return type

[**Empty**](Empty.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_note**
> Note get_note(projects_id, notes_id)



Returns the requested occurrence

### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.GrafeasApi()
projects_id = 'projects_id_example' # str | Part of `name`. The name of the note in the form \"projects/{project_id}/notes/{note_id}\"
notes_id = 'notes_id_example' # str | Part of `name`. See documentation of `projectsId`.

try: 
    api_response = api_instance.get_note(projects_id, notes_id)
    pprint(api_response)
except ApiException as e:
    print "Exception when calling GrafeasApi->get_note: %s\n" % e
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **projects_id** | **str**| Part of &#x60;name&#x60;. The name of the note in the form \&quot;projects/{project_id}/notes/{note_id}\&quot; | 
 **notes_id** | **str**| Part of &#x60;name&#x60;. See documentation of &#x60;projectsId&#x60;. | 

### Return type

[**Note**](Note.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_occurrence**
> Occurrence get_occurrence(projects_id, occurrences_id)



Returns the requested occurrence

### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.GrafeasApi()
projects_id = 'projects_id_example' # str | Part of `name`. The name of the occurrence in the form \"projects/{project_id}/occurrences/{occurrence_id}\"
occurrences_id = 'occurrences_id_example' # str | Part of `name`. See documentation of `projectsId`.

try: 
    api_response = api_instance.get_occurrence(projects_id, occurrences_id)
    pprint(api_response)
except ApiException as e:
    print "Exception when calling GrafeasApi->get_occurrence: %s\n" % e
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **projects_id** | **str**| Part of &#x60;name&#x60;. The name of the occurrence in the form \&quot;projects/{project_id}/occurrences/{occurrence_id}\&quot; | 
 **occurrences_id** | **str**| Part of &#x60;name&#x60;. See documentation of &#x60;projectsId&#x60;. | 

### Return type

[**Occurrence**](Occurrence.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_occurrence_note**
> Note get_occurrence_note(projects_id, occurrences_id)



Gets the note that this occurrence is attached to.

### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.GrafeasApi()
projects_id = 'projects_id_example' # str | Part of `name`. The name of the occurrence in the form \"projects/{project_id}/occurrences/{occurrence_id}\"
occurrences_id = 'occurrences_id_example' # str | Part of `name`. See documentation of `projectsId`.

try: 
    api_response = api_instance.get_occurrence_note(projects_id, occurrences_id)
    pprint(api_response)
except ApiException as e:
    print "Exception when calling GrafeasApi->get_occurrence_note: %s\n" % e
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **projects_id** | **str**| Part of &#x60;name&#x60;. The name of the occurrence in the form \&quot;projects/{project_id}/occurrences/{occurrence_id}\&quot; | 
 **occurrences_id** | **str**| Part of &#x60;name&#x60;. See documentation of &#x60;projectsId&#x60;. | 

### Return type

[**Note**](Note.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_operation**
> Operation get_operation(projects_id, operations_id)



Returns the requested occurrence

### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.GrafeasApi()
projects_id = 'projects_id_example' # str | Part of `name`. The name of the operation in the form \"projects/{project_id}/operations/{operation_id}\"
operations_id = 'operations_id_example' # str | Part of `name`. See documentation of `projectsId`.

try: 
    api_response = api_instance.get_operation(projects_id, operations_id)
    pprint(api_response)
except ApiException as e:
    print "Exception when calling GrafeasApi->get_operation: %s\n" % e
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **projects_id** | **str**| Part of &#x60;name&#x60;. The name of the operation in the form \&quot;projects/{project_id}/operations/{operation_id}\&quot; | 
 **operations_id** | **str**| Part of &#x60;name&#x60;. See documentation of &#x60;projectsId&#x60;. | 

### Return type

[**Operation**](Operation.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **list_note_occurrences**
> ListNoteOccurrencesResponse list_note_occurrences(projects_id, notes_id, filter=filter, page_size=page_size, page_token=page_token)



Lists the names of Occurrences linked to a particular Note.

### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.GrafeasApi()
projects_id = 'projects_id_example' # str | Part of `name`. The name field will contain the note name for example:   \"project/{project_id}/notes/{note_id}\"
notes_id = 'notes_id_example' # str | Part of `name`. See documentation of `projectsId`.
filter = 'filter_example' # str | The filter expression. (optional)
page_size = 56 # int | Number of notes to return in the list. (optional)
page_token = 'page_token_example' # str | Token to provide to skip to a particular spot in the list. (optional)

try: 
    api_response = api_instance.list_note_occurrences(projects_id, notes_id, filter=filter, page_size=page_size, page_token=page_token)
    pprint(api_response)
except ApiException as e:
    print "Exception when calling GrafeasApi->list_note_occurrences: %s\n" % e
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **projects_id** | **str**| Part of &#x60;name&#x60;. The name field will contain the note name for example:   \&quot;project/{project_id}/notes/{note_id}\&quot; | 
 **notes_id** | **str**| Part of &#x60;name&#x60;. See documentation of &#x60;projectsId&#x60;. | 
 **filter** | **str**| The filter expression. | [optional] 
 **page_size** | **int**| Number of notes to return in the list. | [optional] 
 **page_token** | **str**| Token to provide to skip to a particular spot in the list. | [optional] 

### Return type

[**ListNoteOccurrencesResponse**](ListNoteOccurrencesResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **list_notes**
> ListNotesResponse list_notes(projects_id, filter=filter, page_size=page_size, page_token=page_token)



Lists all notes for a given project.

### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.GrafeasApi()
projects_id = 'projects_id_example' # str | Part of `parent`. This field contains the projectId for example: \"project/{project_id}
filter = 'filter_example' # str | The filter expression. (optional)
page_size = 56 # int | Number of notes to return in the list. (optional)
page_token = 'page_token_example' # str | Token to provide to skip to a particular spot in the list. (optional)

try: 
    api_response = api_instance.list_notes(projects_id, filter=filter, page_size=page_size, page_token=page_token)
    pprint(api_response)
except ApiException as e:
    print "Exception when calling GrafeasApi->list_notes: %s\n" % e
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **projects_id** | **str**| Part of &#x60;parent&#x60;. This field contains the projectId for example: \&quot;project/{project_id} | 
 **filter** | **str**| The filter expression. | [optional] 
 **page_size** | **int**| Number of notes to return in the list. | [optional] 
 **page_token** | **str**| Token to provide to skip to a particular spot in the list. | [optional] 

### Return type

[**ListNotesResponse**](ListNotesResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **list_occurrences**
> ListOccurrencesResponse list_occurrences(projects_id, filter=filter, page_size=page_size, page_token=page_token)



Lists active occurrences for a given project/Digest.

### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.GrafeasApi()
projects_id = 'projects_id_example' # str | Part of `parent`. This contains the projectId for example: projects/{project_id}
filter = 'filter_example' # str | The filter expression. (optional)
page_size = 56 # int | Number of occurrences to return in the list. (optional)
page_token = 'page_token_example' # str | Token to provide to skip to a particular spot in the list. (optional)

try: 
    api_response = api_instance.list_occurrences(projects_id, filter=filter, page_size=page_size, page_token=page_token)
    pprint(api_response)
except ApiException as e:
    print "Exception when calling GrafeasApi->list_occurrences: %s\n" % e
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **projects_id** | **str**| Part of &#x60;parent&#x60;. This contains the projectId for example: projects/{project_id} | 
 **filter** | **str**| The filter expression. | [optional] 
 **page_size** | **int**| Number of occurrences to return in the list. | [optional] 
 **page_token** | **str**| Token to provide to skip to a particular spot in the list. | [optional] 

### Return type

[**ListOccurrencesResponse**](ListOccurrencesResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **list_operations**
> ListOperationsResponse list_operations(projects_id, filter=filter, page_size=page_size, page_token=page_token)



Lists all operations for a given project.

### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.GrafeasApi()
projects_id = 'projects_id_example' # str | Part of `parent`. This field contains the projectId for example: \"project/{project_id}
filter = 'filter_example' # str | The filter expression. (optional)
page_size = 56 # int | Number of operations to return in the list. (optional)
page_token = 'page_token_example' # str | Token to provide to skip to a particular spot in the list. (optional)

try: 
    api_response = api_instance.list_operations(projects_id, filter=filter, page_size=page_size, page_token=page_token)
    pprint(api_response)
except ApiException as e:
    print "Exception when calling GrafeasApi->list_operations: %s\n" % e
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **projects_id** | **str**| Part of &#x60;parent&#x60;. This field contains the projectId for example: \&quot;project/{project_id} | 
 **filter** | **str**| The filter expression. | [optional] 
 **page_size** | **int**| Number of operations to return in the list. | [optional] 
 **page_token** | **str**| Token to provide to skip to a particular spot in the list. | [optional] 

### Return type

[**ListOperationsResponse**](ListOperationsResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **update_note**
> Note update_note(projects_id, notes_id, note=note)



Updates an existing note.

### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.GrafeasApi()
projects_id = 'projects_id_example' # str | Part of `name`. The name of the note. Should be of the form \"projects/{project_id}/notes/{note_id}\".
notes_id = 'notes_id_example' # str | Part of `name`. See documentation of `projectsId`.
note = swagger_client.Note() # Note | The updated note. (optional)

try: 
    api_response = api_instance.update_note(projects_id, notes_id, note=note)
    pprint(api_response)
except ApiException as e:
    print "Exception when calling GrafeasApi->update_note: %s\n" % e
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **projects_id** | **str**| Part of &#x60;name&#x60;. The name of the note. Should be of the form \&quot;projects/{project_id}/notes/{note_id}\&quot;. | 
 **notes_id** | **str**| Part of &#x60;name&#x60;. See documentation of &#x60;projectsId&#x60;. | 
 **note** | [**Note**](Note.md)| The updated note. | [optional] 

### Return type

[**Note**](Note.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **update_occurrence**
> Occurrence update_occurrence(projects_id, occurrences_id, occurrence=occurrence)



Updates an existing occurrence.

### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.GrafeasApi()
projects_id = 'projects_id_example' # str | Part of `name`. The name of the occurrence. Should be of the form \"projects/{project_id}/occurrences/{occurrence_id}\".
occurrences_id = 'occurrences_id_example' # str | Part of `name`. See documentation of `projectsId`.
occurrence = swagger_client.Occurrence() # Occurrence | The updated occurrence. (optional)

try: 
    api_response = api_instance.update_occurrence(projects_id, occurrences_id, occurrence=occurrence)
    pprint(api_response)
except ApiException as e:
    print "Exception when calling GrafeasApi->update_occurrence: %s\n" % e
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **projects_id** | **str**| Part of &#x60;name&#x60;. The name of the occurrence. Should be of the form \&quot;projects/{project_id}/occurrences/{occurrence_id}\&quot;. | 
 **occurrences_id** | **str**| Part of &#x60;name&#x60;. See documentation of &#x60;projectsId&#x60;. | 
 **occurrence** | [**Occurrence**](Occurrence.md)| The updated occurrence. | [optional] 

### Return type

[**Occurrence**](Occurrence.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **update_operation**
> Operation update_operation(projects_id, operations_id, body=body)



Updates an existing operation returns an error if operation  does not exist. The only valid operations are to update mark the done bit change the result.

### Example 
```python
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = swagger_client.GrafeasApi()
projects_id = 'projects_id_example' # str | Part of `name`. The name of the Operation. Should be of the form \"projects/{project_id}/operations/{operation_id}\".
operations_id = 'operations_id_example' # str | Part of `name`. See documentation of `projectsId`.
body = swagger_client.UpdateOperationRequest() # UpdateOperationRequest | The request body. (optional)

try: 
    api_response = api_instance.update_operation(projects_id, operations_id, body=body)
    pprint(api_response)
except ApiException as e:
    print "Exception when calling GrafeasApi->update_operation: %s\n" % e
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **projects_id** | **str**| Part of &#x60;name&#x60;. The name of the Operation. Should be of the form \&quot;projects/{project_id}/operations/{operation_id}\&quot;. | 
 **operations_id** | **str**| Part of &#x60;name&#x60;. See documentation of &#x60;projectsId&#x60;. | 
 **body** | [**UpdateOperationRequest**](UpdateOperationRequest.md)| The request body. | [optional] 

### Return type

[**Operation**](Operation.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

