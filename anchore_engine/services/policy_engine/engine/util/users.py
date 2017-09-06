SYSTEM_USER_ID = 'admin'  # The system user is always user '0'.


def is_system_user(user_id):
    return user_id == SYSTEM_USER_ID


def user_ids_to_search(obj):
    """
    Returns an ordered list of user_ids to search for finding related resources for the given object (typically an image or package).

    By strength of match, first element is the same user_id as the given object if the given object has a user_id and the second element of
     the result is the system user id.

    :param obj:
    :return:
    """
    user_ids = []
    if hasattr(obj, 'user_id'):
        user_ids.append(obj.user_id)
        if is_system_user(obj.user_id):
            return user_ids

    user_ids.append(SYSTEM_USER_ID)

    return user_ids
