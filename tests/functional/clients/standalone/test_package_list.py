# TODO from ['image']['imagedata']['analysis_report']['package_list']


class TestGemPackages:

    # defaults to centos 8 
    def test_gem_packages(self, analyzed_data):
        result = analyzed_data("allthethings")
        assert True