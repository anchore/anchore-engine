from anchore_engine.apis.serialization import JitSchema, JsonMappedMixin
from marshmallow import fields, post_load


class DistroMapping(JsonMappedMixin):
    class DistroMappingV1Schema(JitSchema):
        from_distro = fields.Str()
        to_distro = fields.Str()
        flavor = fields.Str()
        created_at = fields.DateTime()

        @post_load
        def make(self, data):
            return DistroMapping(**data)

    __schema__ = DistroMappingV1Schema()

    def __init__(self, from_distro=None, to_distro=None, flavor=None, created_at=None):  # noqa: E501
        self.from_distro = from_distro
        self.to_distro = to_distro
        self.flavor = flavor
        self.created_at = created_at


class ErrorResponse(JsonMappedMixin):
    class ErrorResponseV1Schema(JitSchema):
        code = fields.Int()
        type = fields.Str()
        message = fields.Str()

        @post_load
        def make(self, data):
            return ErrorResponse(**data)

    __schema__ = ErrorResponseV1Schema()

    def __init__(self, code=None, type=None, message=None):  # noqa: E501
        self.code = code
        self.type = type
        self.message = message


class EventStatus(JsonMappedMixin):
    class EventStatusV1Schema(JitSchema):
        event_id = fields.Str()
        event_timestamp = fields.DateTime()
        event_state = fields.Str()

        @post_load
        def make(self, data):
            return EventStatus(**data)

    def __init__(self, event_id=None, event_timestamp=None, event_state=None):  # noqa: E501
        self.event_id = event_id
        self.event_timestamp = event_timestamp
        self.event_state = event_state


class FeedGroupMetadata(JsonMappedMixin):
    class FeedGroupMetadataV1Schema(JitSchema):
        name = fields.Str()
        created_at = fields.DateTime()
        updated_at = fields.DateTime()
        last_sync = fields.DateTime()
        enabled = fields.Boolean()
        record_count = fields.Integer()

        @post_load
        def make(self, data):
            return FeedGroupMetadata(**data)

    __schema__ = FeedGroupMetadataV1Schema()

    def __init__(self, name=None, created_at=None, last_sync=None, record_count=None, enabled=None, updated_at=None):  # noqa: E501
        self.name = name
        self.created_at = created_at
        self.last_sync = last_sync
        self.record_count = record_count
        self.enabled = enabled
        self.updated_at = updated_at


class FeedMetadata(JsonMappedMixin):
    class FeedMetadataV1Schema(JitSchema):
        name = fields.Str()
        created_at = fields.DateTime()
        updated_at = fields.DateTime()
        last_full_sync = fields.DateTime()
        enabled = fields.Boolean()
        groups = fields.List(fields.Nested(FeedGroupMetadata.FeedGroupMetadataV1Schema))

        @post_load
        def make(self, data):
            return FeedMetadata(**data)

    __schema__ = FeedMetadataV1Schema()

    def __init__(self, name=None, created_at=None, updated_at=None, groups=None, last_full_sync=None, enabled=None):
        self.name = name
        self.created_aat = created_at
        self.updated_at = updated_at
        self.groups = groups
        self.last_full_sync = last_full_sync
        self.enabled = enabled


class Image(JsonMappedMixin):
    class ImageV1Schema(JitSchema):
        id = fields.Str()
        digest = fields.Str()
        user_id = fields.Str()
        state = fields.Str()
        distro_namespace = fields.Str()
        created_at = fields.DateTime()
        last_modified = fields.DateTime()
        tags = fields.List(fields.Str())

        @post_load
        def make(self, data):
            return Image(**data)

    __schema__ = ImageV1Schema()

    def __init__(self, id=None, digest=None, user_id=None, state=None, distro_namespace=None, created_at=None, last_modified=None, tags=None):  # noqa: E501
        self.id = id
        self.digest = digest
        self.user_id = user_id
        self.state = state
        self.distro_namespace = distro_namespace
        self.created_at = created_at
        self.last_modified = last_modified
        self.tags = tags


class CvssScore(JsonMappedMixin):
    class CvssScoreV1Schema(JitSchema):
        base_score = fields.Float()
        exploitability_score = fields.Float()
        impact_score = fields.Float()

        @post_load
        def make(self, data):
            return CvssScore(**data)

    __schema__ = CvssScoreV1Schema()

    def __init__(self, base_score=None, exploitability_score=None, impact_score=None):
        self.base_score = base_score
        self.exploitability_score = exploitability_score
        self.impact_score = impact_score


class CvssCombined(JsonMappedMixin):
    class CvssCombinedV1Schema(JitSchema):
        id = fields.Str()
        cvss_v2 = fields.Nested(CvssScore.CvssScoreV1Schema)
        cvss_v3 = fields.Nested(CvssScore.CvssScoreV1Schema)

        @post_load
        def make(self, data):
            return CvssCombined(**data)

    __schema__ = CvssCombinedV1Schema()

    def __init__(self, id=None, cvss_v2=None, cvss_v3=None):
        self.id = id
        self.cvss_v2 = cvss_v2
        self.cvss_v3 = cvss_v3


class CpeVulnerability(JsonMappedMixin):
    class CpeVulnerabilityV1Schema(JitSchema):
        vulnerability_id = fields.Str()
        severity = fields.Str()
        link = fields.Str()
        pkg_type = fields.Str()
        pkg_path = fields.Str()
        name = fields.Str()
        version = fields.Str()
        cpe = fields.Str()
        cpe23 = fields.Str()
        feed_name = fields.Str()
        feed_namespace = fields.Str()
        nvd_data = fields.List(fields.Nested(CvssCombined.CvssCombinedV1Schema))
        vendor_data = fields.List(fields.Nested(CvssCombined.CvssCombinedV1Schema))
        fixed_in = fields.List(fields.Str())

        @post_load
        def make(self, data):
            return CpeVulnerability(**data)

    __schema__ = CpeVulnerabilityV1Schema()

    def __init__(self, vulnerability_id=None, severity=None, link=None, pkg_type=None, pkg_path=None, name=None, version=None, cpe=None, cpe23=None, feed_name=None, feed_namespace=None, nvd_data=None, vendor_data=None, fixed_in=None):
        self.vulnerability_id = vulnerability_id
        self.severity = severity
        self.link = link
        self.pkg_type = pkg_type
        self.pkg_path = pkg_path
        self.name = name
        self.version = version
        self.cpe = cpe
        self.cpe23 = cpe23
        self.feed_name = feed_name
        self.feed_namespace = feed_namespace
        self.nvd_data = nvd_data
        self.vendor_data = vendor_data
        self.fixed_id = fixed_in


class LegacyTableReport(JsonMappedMixin):
    class LegacyTableReportV1Schema(JitSchema):
        rowcount = fields.Int()
        colcount = fields.Int()
        header = fields.List(fields.Str())
        rows = fields.List(fields.List(fields.Str()))

        @post_load
        def make(self, data):
            return LegacyTableReport(**data)

    __schema__ = LegacyTableReportV1Schema()

    def __init__(self, rowcount=None, colcount=None, header=None, rows=None):
        self.rowcount = rowcount
        self.colcount = colcount
        self.header = header
        self.rows = rows


class LegacyMultiReport(JsonMappedMixin):
    class LegacyMultiReportV1Schema(JitSchema):
        url_column_index = fields.Int()
        result = fields.Nested(LegacyTableReport.LegacyTableReportV1Schema)
        warns = fields.List(fields.Str())

        @post_load
        def make(self, data):
            return LegacyMultiReport(**data)

    __schema__ = LegacyMultiReportV1Schema()

    def __init__(self, url_column_index=None, result=None, warns=None):
        self.url_column_index = url_column_index
        self.result = result
        self.warns = warns


class LegacyVulnerabilityReport(JsonMappedMixin):
    class LegacyVulnerabilityReportV1Schema(JitSchema):
        multi = fields.Nested(LegacyMultiReport.LegacyMultiReportV1Schema)

        @post_load
        def make(self, data):
            return LegacyVulnerabilityReport(**data)

    __schema__ = LegacyVulnerabilityReportV1Schema()

    def __init__(self, multi=None):
        self.multi = multi


class ImageVulnerabilityListing(JsonMappedMixin):
    class ImageVulnerabilityListingV1Schema(JitSchema):
        user_id = fields.Str()
        image_id = fields.Str()
        legacy_report = fields.Nested(LegacyVulnerabilityReport.LegacyVulnerabilityReportV1Schema)
        cpe_report = fields.List(fields.Nested(CpeVulnerability.CpeVulnerabilityV1Schema))

        @post_load
        def make(self, data):
            return ImageVulnerabilityListing(**data)

    __schema__ = ImageVulnerabilityListingV1Schema()

    def __init__(self, user_id=None, image_id=None, legacy_report=None, cpe_report=None):  # noqa: E501
        """ImageVulnerabilityListing - a model defined in Swagger

        :param user_id: The user_id of this ImageVulnerabilityListing.  # noqa: E501
        :type user_id: str
        :param image_id: The image_id of this ImageVulnerabilityListing.  # noqa: E501
        :type image_id: str
        :param legacy_report: The legacy_report of this ImageVulnerabilityListing.  # noqa: E501
        :type legacy_report: LegacyVulnerabilityReport
        """
        self.user_id = user_id
        self.image_id = image_id
        self.legacy_report = legacy_report
        self.cpe_report = cpe_report


class ImageIngressRequest(JsonMappedMixin):
    class ImageIngressRequestV1Schema(JitSchema):
        user_id = fields.Str()
        image_id = fields.Str()
        fetch_url = fields.Str() # Could use a Url() here but one of the scheme options we use 'catalog://' isn't valid in their regex, bug in the Url() field code for custom schema support

        @post_load
        def make(self, data):
            return ImageIngressRequest(**data)

    __schema__ = ImageIngressRequestV1Schema()

    def __init__(self, user_id=None, image_id=None, fetch_url=None):
        self.user_id = user_id
        self.image_id = image_id
        self.fetch_url = fetch_url


class ImageIngressResponse(JsonMappedMixin):
    class ImageIngressResponseV1Schema(JitSchema):
        status = fields.Str()

        @post_load
        def make(self, data):
            return ImageIngressResponse(**data)

    __schema__ = ImageIngressResponseV1Schema()

    def __init__(self, status=None):
        self.status = status


class TriggerParamSpec(JsonMappedMixin):
    class TriggerParamSpecV1Schema(JitSchema):
        name = fields.Str()
        description = fields.Str()
        example = fields.Str()
        required = fields.Bool()
        state = fields.Str()
        superceded_by = fields.Str()
        validator = fields.Dict()

        @post_load
        def make(self, data):
            return TriggerParamSpec(**data)

    __schema__ = TriggerParamSpecV1Schema()

    def __init__(self, name=None, description=None, example=None, required=None, state=None, superceded_by=None, validator=None):
        self.name = name
        self.description = description
        self.example = example
        self.required = required
        self.state = state
        self.superceded_by = superceded_by
        self.validator = validator


class TriggerSpec(JsonMappedMixin):
    class TriggerSpecV1Schema(JitSchema):
        name = fields.Str()
        description = fields.Str()
        state = fields.Str()
        superceded_by = fields.Str()
        parameters = fields.List(fields.Nested(TriggerParamSpec.TriggerParamSpecV1Schema))

        @post_load
        def make(self, data):
            return TriggerSpec(**data)

    __schema__ = TriggerSpecV1Schema()

    def __init__(self, name=None, description=None, state=None, superceded_by=None, parameters=None):
        self.name = name
        self.description = description
        self.state = state
        self.superceded_by = superceded_by
        self.parameters = parameters


class GateSpec(JsonMappedMixin):
    class GateSpecV1Schema(JitSchema):
        name = fields.Str()
        description = fields.Str()
        state = fields.Str()
        superceded_by = fields.Str()
        triggers = fields.List(fields.Nested(TriggerSpec.TriggerSpecV1Schema))

        @post_load
        def make(self, data):
            return GateSpec(**data)

    __schema__ = GateSpecV1Schema()

    def __init__(self, name=None, description=None, state=None, superceded_by=None, triggers=None):
        self.name = name
        self.description = description
        self.state = state
        self.superceded_by = superceded_by
        self.triggers = triggers


class PolicyEvaluationProblem(JsonMappedMixin):
    class PolicyEvaluationProblemV1Schema(JitSchema):
        severity = fields.Str()
        problem_type = fields.Str()
        details = fields.Str()

        @post_load
        def make(self, data):
            return PolicyEvaluationProblem(**data)

    __schema__ = PolicyEvaluationProblemV1Schema()

    def __init__(self, severity=None, problem_type=None, details=None):
        self.severity = severity
        self.problem_type = problem_type
        self.details = details


class PolicyEvaluation(JsonMappedMixin):
    class PolicyEvaluationV1Schema(JitSchema):
        user_id = fields.Str()
        image_id = fields.Str()
        tag = fields.Str()
        bundle = fields.Dict()
        matched_mapping_rule = fields.Dict()
        matched_whitelisted_images_rule = fields.Dict()
        matched_blacklisted_images_rule = fields.Dict()
        result = fields.Dict()
        created_at = fields.Int()
        last_modified = fields.Int()
        final_action = fields.Str()
        final_action_reason = fields.Str()
        evaluation_problems = fields.List(fields.Nested(PolicyEvaluationProblem.PolicyEvaluationProblemV1Schema))

        @post_load
        def make(self, data):
            return PolicyEvaluation(**data)

    __schema__ = PolicyEvaluationV1Schema()

    def __init__(self, user_id=None, image_id=None, tag=None, bundle=None, matched_mapping_rule=None, matched_whitelisted_images_rule=None,
                 matched_blacklisted_images_rule=None, result=None, created_at=None, last_modified=None, final_action=None,
                 final_action_reason=None, evaluation_problems=None):
        self.user_id = user_id
        self.image_id = image_id
        self.tag = tag
        self.bundle = bundle
        self.matched_mapping_rule = matched_mapping_rule
        self.matched_whitelisted_images_rule = matched_whitelisted_images_rule
        self.matched_blacklisted_images_rule = matched_blacklisted_images_rule
        self.result = result
        self.created_at = created_at
        self.last_modified = last_modified
        self.final_action = final_action
        self.final_action_reason = final_action_reason
        self.evaluation_problems = evaluation_problems


class PolicyValidationResponse(JsonMappedMixin):
    class PolicyValidationResponseV1Schema(JitSchema):
        valid = fields.Bool()
        validation_details = fields.List(fields.Nested(PolicyEvaluationProblem.PolicyEvaluationProblemV1Schema))

        @post_load
        def make(self, data):
            return PolicyValidationResponse(**data)

    __schema__ = PolicyValidationResponseV1Schema()

    def __init__(self, valid=None, validation_details=None):
        self.valid = valid
        self.validation_details = validation_details
