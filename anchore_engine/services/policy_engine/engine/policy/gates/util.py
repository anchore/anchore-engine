from collections import namedtuple

CheckOperation = namedtuple('CheckOperation', ['requires_rvalue', 'eval_function'])


def deprecated_operation(superceded_by=None):
    """
    Decorator to mark an operation (gate, trigger, etc) as deprecated.
    :param superceded_by: Thee name of the similar operation that supercedes the decorated one, if applicable
    :return:
    """

    def decorator(cls):
        setattr(cls, '__is_deprecated__', True)
        setattr(cls, '__superceded_by__', superceded_by)
        return cls
    return decorator


def end_of_lifed_operation(superceded_by=None):
    """
    Decorator to mark an operation (gate, trigger, etc) as deprecated.
    :param superceded_by: Thee name of the similar operation that supercedes the decorated one, if applicable
    :return:
    """

    def no_op_evaluate(*args, **kwargs):
        """
        A no-op version of the evaluate function
        :param args:
        :return:
        """
        return None, None

    def decorator(cls):
        setattr(cls, '__is_deprecated__', True)
        setattr(cls, '__superceded_by__', superceded_by)
        setattr(cls, 'evaluate', no_op_evaluate)
        return cls

    return decorator
