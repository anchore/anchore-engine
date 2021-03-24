import pytest

base_secrets = [
    (
        "/home/test_api_key",
        '{"QVBJX0tFWT0oP2kpLiphcGkoLXxfKWtleSggKj0rICopLiooPzwhW0EtWjAtOV0pW0EtWjAtOV17\\nMjAsNjB9KD8hW0EtWjAtOV0pLio=\\n": [0]}',
    ),
    (
        "/home/test_aws_access_key",
        '{"QVdTX0FDQ0VTU19LRVk9KD9pKS4qYXdzX2FjY2Vzc19rZXlfaWQoICo9KyAqKS4qKD88IVtBLVow\\nLTldKVtBLVowLTldezIwfSg/IVtBLVowLTldKS4q\\n": [0]}',
    ),
    (
        "/home/test_aws_secret_key",
        '{"QVdTX1NFQ1JFVF9LRVk9KD9pKS4qYXdzX3NlY3JldF9hY2Nlc3Nfa2V5KCAqPSsgKikuKig/PCFb\\nQS1aYS16MC05Lys9XSlbQS1aYS16MC05Lys9XXs0MH0oPyFbQS1aYS16MC05Lys9XSkuKg==\\n": [0]}',
    ),
    (
        "/home/test_docker_config",
        '{"RE9DS0VSX0FVVEg9KD9pKS4qImF1dGgiOiAqIi4rIg==\\n": [4]}',
    ),
    (
        "/home/test_rsa_key",
        '{"UFJJVl9LRVk9KD9pKS0rQkVHSU4oLiopUFJJVkFURSBLRVktKw==\\n": [0]}',
    ),
]


@pytest.mark.parametrize("path, secret", base_secrets)
def test_secret_content_search(analyzed_data, path, secret):
    data = analyzed_data("secrets")
    base = data["image"]["imagedata"]["analysis_report"]["secret_search"][
        "regexp_matches.all"
    ]["base"]
    assert base[path] == secret
