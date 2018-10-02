from anchore_engine.services.policy_engine.engine import logs
logs.test_mode = True


def init_test_logging(level='DEBUG', output_file=None):
    """
    Initialize logging configured to use a standard logger rather than a twistd logger
    :return:
    """
    import logging

    if not output_file:
        logging.basicConfig(level=level)
    else:
        logging.basicConfig(level=level, filename=output_file)
