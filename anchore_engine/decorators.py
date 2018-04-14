"""
Generic decorators for use in all parts of the system
"""


def delegate_to_callable(fn, err_msg=None):
    """
    Delegate a call of the same name to the object returned by the fn() invocation. Useful for lazy initializers and functions
    that return a common singleton. Can be used to hoist a singleton objects functions to module level

    Example usage:

    singleton = None

    class A(object):
      def test():
        return 'abc'

    def get_singleton():
      global singleton
      if singleton is None:
        singleton = A()
      return singleton

    @delegate_to_callable(get_singleton)
    def test():
      pass

    :param fn:
    :return:
    """
    def outer_wrapper(f):
        def inner_wrapper(*args, **kwargs):
            obj = fn()
            if obj is None:
                raise Exception('Delegate object not available. Err: {}'.format(err_msg))

            if not hasattr(obj, f.__name__):
                raise Exception('Cannot delegate {} to {}, no attribute to delegate to'.format(f.__name__, str(obj)))
            delegated_attr = getattr(obj, f.__name__)
            if not callable(delegated_attr):
                raise Exception('Cannot delegate {} to {} due to not a callable attribute'.format(f.__name__,
                                                                                                  delegated_attr.__name__))

            return delegated_attr(*args, **kwargs)
        return inner_wrapper
    return outer_wrapper
