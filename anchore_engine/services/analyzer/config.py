PACKAGE_FILTERING_ENABLED_KEY = "enable_owned_package_filtering"


def extract_service_config(global_config: dict):
    return global_config.get("services", {}).get("analyzer", {})


def get_bool_value(input_value) -> bool:
    return (
        input_value.lower() == "true" if type(input_value) == str else bool(input_value)
    )
