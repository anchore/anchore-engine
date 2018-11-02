from anchore_engine.utils import AnchoreException


class TagManifestParseError(AnchoreException):
    def __init__(self, cause, tag, manifest, msg='Failed to parse manifest'):
        self.cause = str(cause)
        self.tag = tag
        self.manifest = str(manifest)
        self.msg = msg

    def __repr__(self):
        return '{} ({}) - exception: {}'.format(self.msg, self.tag, self.cause)

    def __str__(self):
        return '{} ({}) - exception: {}'.format(self.msg, self.tag, self.cause)


class TagManifestNotFoundError(AnchoreException):
    def __init__(self, tag, msg='Tag manifest not found'):
        self.tag = tag
        self.msg = msg

    def __repr__(self):
        return '{} ({})'.format(self.msg, self.tag)

    def __str__(self):
        return '{} ({})'.format(self.msg, self.tag)


class PolicyBundleDownloadError(AnchoreException):
    def __init__(self, url, status, cause, msg='Failed to download policy bundle'):
        self.url = url
        self.status = status
        self.cause = cause
        self.msg = msg

    def __repr__(self):
        return '{} ({}) - exception: {}'.format(self.msg, self.url, self.cause)

    def __str__(self):
        return '{} ({}) - exception: {}'.format(self.msg, self.url, self.cause)


class PolicyBundleValidationError(AnchoreException):
    def __init__(self, cause, msg='Policy bundle validation failed'):
        self.cause = cause
        self.msg = msg

    def __repr__(self):
        return '{} - cause: {}'.format(self.msg, self.cause)

    def __str__(self):
        return '{} - cause: {}'.format(self.msg, self.cause)


