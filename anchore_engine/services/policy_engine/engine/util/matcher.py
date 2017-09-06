import re


def regexify(pattern):
    """
    Normalize the wildcard pattern into a valid regex

    :param pattern:
    :return:
    """
    match_tokens = []
    for tok in pattern.split("*"):
        match_tokens.append(re.escape(tok))
    return "^" + '(.*)'.join(match_tokens) + "$"


def is_match(sanitizer, pattern, input_str):
    """
    Utility method for running a pattern through the sanitizer and evaluating the input against generated regex
     
    :param sanitizer:
    :param pattern:
    :param input_str:
    :return:
    """
    sanitized = sanitizer(pattern)
    return True if re.match(sanitized, input_str) else False
