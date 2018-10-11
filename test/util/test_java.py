import unittest
import anchore_engine.util.java as java_util

class TestJava(unittest.TestCase):
    
    def test_parse_properties(self):
        properties = """
        foo = bar
        # commented = yes
        test = true
        """
        
        props = java_util.parse_properties(properties.splitlines())

        self.assertEqual('bar', props['foo'])
        self.assertEqual('true', props['test'])
        self.assertNotIn('commented', props)

