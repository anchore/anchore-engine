from . import alpine
from . import gem
from . import java
from . import npm
from . import python
from . import rpm

# this is a mapping of syft artifact types to handler functions to transform syft output into engine-compliant output
handlers_by_artifact_type = {
    'gem': gem.handler,
    'python': python.handler,
    'npm': npm.handler,
    'java-archive': java.handler,
    'jenkins-plugin': java.handler,
    'apk': alpine.handler,
    'rpm': rpm.handler,
}
