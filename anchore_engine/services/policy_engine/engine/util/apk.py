"""
Utilities for working with APK packages in Alpine images

"""
import enum
import copy


class ComparisonResult(enum.IntEnum):
    less_than = -1
    equal_to = 0
    greater_than = 1


class TokenType(enum.IntEnum):
    INVALID = -1,
    DIGIT_OR_ZERO = 0,
    DIGIT = 1,
    LETTER = 2,
    SUFFIX = 3,
    SUFFIX_NO = 4,
    REVISION_NO = 5,
    END = 6


# Ordering of these lists is important for evaluation correctness. Positions in the list are used for relative comparison
pre_release_suffixes = ['alpha', 'beta', 'pre', 'rc']
post_release_suffixes = ['cvs', 'svn', 'git', 'hg', 'p']


def next_token(expected_type, data):
    """
    Based on the expected next type, consume the next token returning the type found and an updated buffer with the found token
    removed

    :param expected_type:
    :param data:
    :return: (TokenType, str) tuple where TokenType is the type of the next token expected

    """
    next_data = copy.copy(data)

    next_type = TokenType.INVALID

    if len(next_data) == 0 or next_data[0] == None:
        next_type = TokenType.END
    elif (expected_type == TokenType.DIGIT or expected_type == TokenType.DIGIT_OR_ZERO) and next_data[0].isalpha():
        next_type = TokenType.LETTER
    elif expected_type == TokenType.LETTER and next_data[0].isdigit():
        next_type = TokenType.DIGIT
    elif expected_type == TokenType.SUFFIX and next_data[0].isdigit():
        next_type = TokenType.SUFFIX_NO
    else:
        if next_data[0] == '.':
            next_type = TokenType.DIGIT_OR_ZERO
        elif next_data[0] == '_':
            next_type = TokenType.SUFFIX
        elif next_data[0] == '-':
            if len(next_data) > 1 and next_data[1] == 'r':
                next_type = TokenType.REVISION_NO
                # Pop leading char off
                next_data = next_data[1:]
            else:
                next_type = TokenType.INVALID

        next_data = next_data[1:]

    if next_type < expected_type:
        if not ((next_type == TokenType.DIGIT_OR_ZERO and expected_type == TokenType.DIGIT) or
                (next_type == TokenType.SUFFIX and expected_type == TokenType.SUFFIX_NO) or
                (next_type == TokenType.DIGIT and expected_type == TokenType.LETTER)):
            next_type = TokenType.INVALID

    return next_type, next_data


def get_token(expected_type, data):
    """
    Given the expected token type and the data, grab the next token and return a tuple of (token, token_type, updated_string)
    :param expected_type: Parts enum value for tthe expected type
    :param data: the str from which to pull next token starting at the beginning
    :return: (token, token_type, new working str)
    """

    token_value = i = 0
    next_token_type = TokenType.INVALID
    d_len = len(data)

    if len(data) <= 0:
        return 0, TokenType.END, data

    if expected_type == TokenType.DIGIT_OR_ZERO and data[i] == '0':
        # Handled leading zeros
        while i < d_len and data[i] == '0':
            i += 1
        next_token_type = TokenType.DIGIT
        token_value = -i
    elif expected_type in [TokenType.DIGIT_OR_ZERO, TokenType.DIGIT, TokenType.SUFFIX_NO, TokenType.REVISION_NO]:
        # Handle numbers
        dig_val = ''
        while i < d_len and data[i].isdigit():
            dig_val += data[i]
            i += 1
        token_value = int(dig_val) if dig_val else 0
    elif expected_type == TokenType.LETTER:
        # Handle letter values
        token_value = ord(data[i])
        i += 1
    elif expected_type == TokenType.SUFFIX:
        idx = -1
        # Is this is a pre-release suffix?
        for s in pre_release_suffixes:
            i = len(s)
            if data.startswith(s):
                idx = pre_release_suffixes.index(s)
                break

        if idx >= 0:
            token_value = idx - len(pre_release_suffixes)
        else:
            idx = -1
            # Try post-release suffixes for a match
            for s in post_release_suffixes:
                i = len(s)
                if data.startswith(s):
                    idx = post_release_suffixes.index(s)
                    break
            if idx < 0:
                # No match found
                return -1, TokenType.INVALID, data
            else:
                token_value = idx
    else:
        return -1, TokenType.INVALID, data

    data = data[i:]
    if len(data) == 0:
        next_token_type = TokenType.END
    elif next_token_type != TokenType.INVALID:
        pass
    else:
        next_token_type, data = next_token(expected_type, data)

    return token_value, next_token_type, data


def get_version_relationship(ver_str1, ver_str2):
    """
    Comparison of alpine package version numbers. Roughly based on the C code from github.com/apk-tools/version.c but in pure python.

    :param ver_str1:
    :param ver_str2:
    :return:
    """

    # Expect first type to be a digit, per Gentoo spec (used by apk)
    v1_type = TokenType.DIGIT
    v2_type = TokenType.DIGIT
    v1_tok = 0
    v2_tok = 0

    if ver_str1 is None and ver_str2 is None:
        return ComparisonResult.equal_to

    if ver_str1 is None and ver_str2 is not None:
        return ComparisonResult.less_than

    if ver_str1 is not None and ver_str2 is None:
        return ComparisonResult.greater_than

    # Find either the end of one string or the first invalid token of first non-equal token pair.
    while v1_type == v2_type and v1_type != TokenType.END and v1_type != TokenType.INVALID and v1_tok == v2_tok:
        v1_tok, v1_type, ver_str1 = get_token(v1_type, ver_str1)
        v2_tok, v2_type, ver_str2 = get_token(v2_type, ver_str2)

    # Check the value of the current token
    if v1_tok < v2_tok:
        return ComparisonResult.less_than

    if v1_tok > v2_tok:
        return ComparisonResult.greater_than

    if v1_type == v2_type:
        return ComparisonResult.equal_to

    if v1_type == TokenType.SUFFIX and get_token(v1_type, ver_str1)[0] < 0:
        return ComparisonResult.less_than

    if v2_type == TokenType.SUFFIX and get_token(v2_type, ver_str2)[0] < 0:
        return ComparisonResult.greater_than

    if v1_type > v2_type:
        return ComparisonResult.less_than

    if v2_type > v1_type:
        return ComparisonResult.greater_than

    return ComparisonResult.equal_to


def compare_versions(v1, op, v2):
    result = get_version_relationship(v1, v2)

    if op == 'eq':
        return result == ComparisonResult.equal_to
    if op == 'lt':
        return result == ComparisonResult.less_than
    if op == 'gt':
        return result == ComparisonResult.greater_than
    else:
        raise ValueError('Unsupported op type', op)

