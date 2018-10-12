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
