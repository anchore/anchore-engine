import anchore_engine.util.java as java_util

def test_parse_properties():
    properties = """
    prop1=val1
    prop2 = val2
    #prop3 = ignored due to comments
      prop4 = val4
    """

    props = java_util.parse_properties(properties.splitlines())

    assert props['prop1'] == 'val1'
    assert props['prop2'] == 'val2'
    assert 'prop3' not in props
    assert props['prop4'] == 'val4'

def test_parse_manifest():
    # a manifest file is similar to HTTP headers, but are limited to
    # 72 character lines (70 characters in practice because \r\n is two
    # bytes). long lines are wrapped to the next line beginning with a space.
    manifest = """
Manifest-Version: 1.0
Built-By: anchore
Long-Attribute: 12345678901234567890123456789012345678901234567890123
 45678901234567890123456789012345678901234567890123456789012345678901
 23456789012345678901234567890123456789012345678901234567890123456789
 0
Another-Attribute: 12345678901234567890123456789012345678901234567890
  with space
    """.strip()

    attrs = java_util.parse_manifest(manifest.splitlines())

    assert 'Manifest-Version' in attrs
    assert attrs['Manifest-Version'] == '1.0'
    assert attrs['Built-By'] == 'anchore'
    assert attrs['Long-Attribute'] == ('1234567890' * 19)
    assert attrs['Another-Attribute'] == ('1234567890' * 5) + ' with space'
