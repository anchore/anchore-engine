import unittest


from anchore_engine.auth.aws_ecr import parse_registry_url


class AWSECRTestCase(unittest.TestCase):

    def test_parse_registry_url_parses_url(self):
        
        urls = [
            '1234567890.dkr.ecr.us-west-2.amazonaws.com',
            '1234567890.dkr.ecr.us-west-2.amazonaws.com/my_app_image',
            'http://1234567890.dkr.ecr.us-west-2.amazonaws.com',
            'http://1234567890.dkr.ecr.us-west-2.amazonaws.com/my_app_image:latest'
        ]
        
        expected = ('1234567890', 'us-west-2')
        
        for url in urls:
            self.assertEqual(expected, parse_registry_url(url))
            
if __name__ == '__main__':
    unittest.main()
    
