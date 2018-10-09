"""
Maven utilities for handling versions and such

"""


class IntegerVersionItem(object):
    _big_integer_zero_ = 0

    def __init__(self, value=None):
        self.value = int(value) if value else self._big_integer_zero_

    def __repr__(self):
        return str(self.value)

    def __str__(self):
        return str(self.value)

    def is_null(self):
        return self.value == self._big_integer_zero_

    def compare_to(self, other):
        if not other:
            return 0 if self.value == self._big_integer_zero_ else 1
        else:
            if type(other) == IntegerVersionItem:
                if self.value == other.value:
                    return 0
                elif self.value > other.value:
                    return 1
                else:
                    return -1
            elif type(other) in [StringVersionItem, ListVersionItem]:
                return 1  # 1.1 > 1-sp 1.1 > 1-1
            else:
                return NotImplemented


class StringVersionItem(object):
    _qualifiers_ = ['alpha', 'beta', 'milestone', 'rc', 'snapshot', '', 'sp']
    _aliases_ = {'ga': '', 'final': '', 'cr': 'rc'}
    _acronyms_ = {'a': 'alpha', 'b': 'beta', 'm': 'milestone'}
    _release_version_index_ = str(_qualifiers_.index(''))

    def __init__(self, value, followed_by_digit):
        if followed_by_digit and value in self._acronyms_:
            value = self._acronyms_[value]

        self.value = self._aliases_.get(value, value)
        self.cq = self.comparable_qualifier(self.value)

    def __repr__(self):
        return self.value

    def __str__(self):
        return self.value

    def is_null(self):
        return self.cq == self._release_version_index_

    def comparable_qualifier(self, qualifier):
        return str(self._qualifiers_.index(qualifier)) if qualifier in self._qualifiers_ else '{}-{}'.format(
            len(self._qualifiers_), qualifier)

    def compare_to(self, other):
        if not other:
            return 0 if self.cq == self._release_version_index_ else (
                1 if self.cq > self._release_version_index_ else -1)
        else:
            if type(other) == StringVersionItem:
                if self.cq == other.cq:
                    return 0
                elif self.cq > other.cq:
                    return 1
                else:
                    return -1
            elif type(other) in [IntegerVersionItem, ListVersionItem]:
                return -1  # 1.any < 1.1 1.any < 1-1
            else:
                return NotImplemented


class ListVersionItem(list):

    def __init__(self):
        super(ListVersionItem, self).__init__()

    def __repr__(self):
        ret = ''
        for version_item in self:
            if ret:
                ret = ret + ('-' if type(version_item) == ListVersionItem else '.') + version_item.__repr__()
            else:
                ret = version_item.__repr__()
        return ret

    def __str__(self):
        return self.__repr__()

    def is_null(self):
        return len(self) == 0

    def normalize(self):
        for index in reversed(range(len(self))):
            if self[index].is_null():
                self.__delitem__(index)
            elif type(self[index]) != ListVersionItem:
                break

    def compare_to(self, other):
        if not other:
            return 0 if len(self) == 0 else self[0].compare_to(None)
        else:
            if type(other) == ListVersionItem:
                l_iter = self.__iter__()
                r_iter = other.__iter__()
                left = next(l_iter, None)
                right = next(r_iter, None)

                while left or right:
                    if left and type(left) in [IntegerVersionItem, StringVersionItem, ListVersionItem]:
                        result = left.compare_to(right)
                    elif right and type(right) in [IntegerVersionItem, StringVersionItem, ListVersionItem]:
                        result = -1 * right.compare_to(left)
                    else:
                        raise NotImplemented

                    if result != 0:
                        return result

                    left = next(l_iter, None)
                    right = next(r_iter, None)

                return 0
            elif type(other) == IntegerVersionItem:
                return -1  # 1-1 < 1.0.x
            elif type(other) == StringVersionItem:
                return 1  # 1-1 > 1-sp


class MavenVersion(object):
    """
    Comparable object that takes a string as input and constructs the canonical Maven version. Two MavenVersion objects
    a and b can be compared using:

    1. instance method compare_to() produces integer result:
        a.compare_to(b) = 0, 1 or -1 if a and b are equal, a is greater than b or a is less than b respectively
    2. rich comparison operators produce boolean result:
        a == b is True if a and are equal
        a >= b is True if a is greater than or equal to b
        a <= b is True if a is less than or equal to b

    Translated into Python from
    https://github.com/apache/maven/blob/d92508179410897404bcc7e826bb0877be2d08b8/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java
    """

    def __init__(self, version):
        self.value = version
        self.items = self._parse_version_(version)
        self.canonical = self.items.__repr__()

    def __repr__(self):
        return self.canonical

    def __str__(self):
        return self.canonical

    def __hash__(self):
        return hash(self.canonical)

    def __eq__(self, other):
        return True if self.compare_to(other) == 0 else False

    def __ne__(self, other):
        return True if self.compare_to(other) != 0 else False

    def __gt__(self, other):
        return True if self.compare_to(other) > 0 else False

    def __lt__(self, other):
        return True if self.compare_to(other) < 0 else False

    def __ge__(self, other):
        return True if self.compare_to(other) >= 0 else False

    def __le__(self, other):
        return True if self.compare_to(other) <= 0 else False

    @staticmethod
    def _get_version_item_(is_digit, version_ss):
        return IntegerVersionItem(version_ss) if is_digit else StringVersionItem(version_ss, False);

    @staticmethod
    def _parse_version_(version):
        ver = str(version).strip().lower()

        items = ListVersionItem()
        wlist = items
        stack = list()
        stack.append(wlist)

        is_digit = False
        start_index = 0

        for c, i in zip(ver, range(len(ver))):
            if c == '.':
                if i == start_index:
                    wlist.append(IntegerVersionItem())
                else:
                    wlist.append(MavenVersion._get_version_item_(is_digit, ver[start_index:i]))

                start_index = i + 1

            elif c == '-':
                if i == start_index:
                    wlist.append(IntegerVersionItem())
                else:
                    wlist.append(MavenVersion._get_version_item_(is_digit, ver[start_index:i]))

                start_index = i + 1
                wlist = ListVersionItem()
                items.append(wlist)
                stack.append(wlist)

            elif str.isdigit(c):
                if not is_digit and i > start_index:
                    wlist.append(StringVersionItem(ver[start_index:i], True))
                    start_index = i

                    wlist = ListVersionItem()
                    items.append(wlist)
                    stack.append(wlist)

                is_digit = True
            else:
                if is_digit and i > start_index:
                    wlist.append(MavenVersion._get_version_item_(True, ver[start_index:i]))
                    start_index = i

                    wlist = ListVersionItem()
                    items.append(wlist)
                    stack.append(wlist)

                is_digit = False

        if len(ver) > start_index:
            wlist.append(MavenVersion._get_version_item_(is_digit, ver[start_index:]))

        while len(stack) > 0:
            wlist = stack.pop()
            wlist.normalize()

        return items

    def compare_to(self, other):
        if type(other) == MavenVersion:
            return self.items.compare_to(other.items)
        else:
            return NotImplemented
