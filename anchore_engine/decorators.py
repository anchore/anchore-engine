import cProfile
import linecache
import os
import pstats
import tracemalloc

import pyinstrument

# from pyinstrument.renderers import JSONRenderer, HTMLRenderer

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
                raise Exception(
                    "Delegate object not available. Err: {}".format(err_msg)
                )

            if not hasattr(obj, f.__name__):
                raise Exception(
                    "Cannot delegate {} to {}, no attribute to delegate to".format(
                        f.__name__, str(obj)
                    )
                )
            delegated_attr = getattr(obj, f.__name__)
            if not callable(delegated_attr):
                raise Exception(
                    "Cannot delegate {} to {} due to not a callable attribute".format(
                        f.__name__, delegated_attr.__name__
                    )
                )

            return delegated_attr(*args, **kwargs)

        return inner_wrapper

    return outer_wrapper


def profile(func):
    def _f(*args, **kwargs):
        pr = cProfile.Profile()
        pr.enable()
        print("\n<<<---*********")
        res = func(*args, **kwargs)
        p = pstats.Stats(pr)
        p.strip_dirs().sort_stats("cumtime").print_stats(20)
        print("\n--->>>*********")
        return res

    return _f


def profile_instrument(func):
    def _f(*args, **kwargs):
        profiler = pyinstrument.Profiler(interval=0.01)  ## Profiler
        print("\n<<<---pyinstrument!")
        profiler.start()
        res = func(*args, **kwargs)
        profiler.stop()
        print(profiler.output_text(color=True))
        print("\n--->>>pyinstrument!")

        # json_output = profiler.output(JSONRenderer(show_all=False, timeline=False))
        # print(json_output)
        return res

    return _f


def tracemalloc_profile(func):
    def _f(*args, **kwargs):
        tracemalloc.start()
        res = func(*args, **kwargs)
        mem_snapshot = tracemalloc.take_snapshot()

        def display_top(snapshot, key_type="traceback", limit=10):
            snapshot = snapshot.filter_traces(
                (
                    tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
                    tracemalloc.Filter(False, "<unknown>"),
                    tracemalloc.Filter(False, linecache.__file__),
                    tracemalloc.Filter(False, tracemalloc.__file__),
                )
            )
            top_stats = snapshot.statistics(key_type)

            print("Top %s lines" % limit)
            for index, stat in enumerate(top_stats[:limit], 1):
                frame = stat.traceback[0]
                print(
                    "#%s: %s:%s: %.1f KiB"
                    % (index, frame.filename, frame.lineno, stat.size / 1024)
                )
                line = linecache.getline(frame.filename, frame.lineno).strip()
                if line:
                    print("    %s" % line)

            other = top_stats[limit:]
            if other:
                size = sum(stat.size for stat in other)
                print("%s other: %.1f KiB" % (len(other), size / 1024))
            total = sum(stat.size for stat in top_stats)
            print("Total allocated size: %.1f KiB" % (total / 1024))

        print(display_top(mem_snapshot))

        return res

    return _f
