"""
api_utils is a module for common anchore api handling functions useful for all/any anchore-engine api
"""
from connexion import request
from collections import namedtuple

AuthenticationContext = namedtuple('AuthenticationContext', field_names=['user_id', 'password'])


def pass_user_context(f):
    """
    A decorator for handling auth info for an api handler to pass AuthenticationContext as the first parameter of the function.
    Useful since connexion/flask doesn't pass header parameters into the handler functions.

    Example:

    @pass_user_context
    def add_image(auth_ctx, image_digest):
      catalog.add_image(user_id=auth_ctx.user_id, image_digest=image_digest)

    :param f:
    :return:
    """
    def decorator(*args, **kwargs):
        if hasattr(request, 'authorization'):
            if hasattr(request.authorization, 'username'):
                user = request.authorization.username
            else:
                user = None
            if hasattr(request.authorization, 'password'):
                passwd = request.authorization.password
            else:
                passwd = None
        else:
            user = None
            passwd = None

        auth_context = AuthenticationContext(user_id=user, password=passwd)
        return f(auth_context, *args, **kwargs)
    return decorator
