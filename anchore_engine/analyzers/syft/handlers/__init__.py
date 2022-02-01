from . import alpine, debian, gem, golang, java, npm, python, rpm

# This is a mapping of **syft** artifact types to modules to transform syft output into engine-compliant output.
# Each module has two functions: translate_and_save_entry & save_entry
modules_by_artifact_type = {
    "gem": gem,
    "python": python,
    "npm": npm,
    "java-archive": java,
    "jenkins-plugin": java,
    "go-module": golang,
    "apk": alpine,
    "rpm": rpm,
    "deb": debian,
}

# This is a mapping of **engine** artifact types to modules to transform syft output into engine-compliant output
# Each module has two functions: translate_and_save_entry & save_entry
modules_by_engine_type = {
    "gem": gem,
    "python": python,
    "npm": npm,
    "java": java,
    "java-jar": java,
    "java-ear": java,
    "java-war": java,
    "java-jpi": java,
    "java-hpi": java,
    "go": golang,
    "apkg": alpine,
    "rpm": rpm,
    "dpkg": debian,
}
