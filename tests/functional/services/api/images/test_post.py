class TestOversizedImageReturns400:
    # Expectation for this test is that the image with tag is greater than the value defined in config
    def test_oversized_image_post(self, make_image_analysis_request):
        resp = make_image_analysis_request("anchore/test_images:oversized_image")

        details = resp.body["detail"]
        msg = resp.body["message"]

        assert resp.code == 400
        assert (
            msg
            == "Image size is too large based on max size specified in the configuration"
        )
        assert (
            details["requested_image_compressed_size"]
            > details["max_compressed_image_size_mb"]
        )


class TestValidImageReturns200:
    def test_valid_image_returns_200(self, make_image_analysis_request):
        resp = make_image_analysis_request("alpine:latest")

        assert resp.code == 200
