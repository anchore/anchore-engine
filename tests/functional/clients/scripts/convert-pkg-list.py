import json

pkgs = [
    # your stuff here...
]


result = {}
for path, metadata in pkgs:
    result[path] = json.loads(metadata)

# run this script with "> result.py" and use your IDE to auto format with black (pprint does not concat strings to a single string, black will)
print(result)
