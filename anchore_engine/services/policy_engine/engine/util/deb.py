"""
Utils for working with debian packages (dpkg and apt).

"""

# Map ops to the conversion from a standard cmp output
compare_operators = {
    'le': lambda x: x <= 0,
    'lt': lambda x: x < 0,
    'eq': lambda x: x == 0,
    'ne': lambda x: x != 0,
    'ge': lambda x: x >= 0,
    'gt': lambda x: x > 0,
}

# See dpkg lib/dpkg/version.h for the dpkg_version struct, which this mirrors
# epoch will be zero if not present
# version is the upstream part of the version
# revision is the debian revision part of the version
class DpkgVersion(object):
    @classmethod
    def blank(cls):
        return DpkgVersion(0, None, None)

    @classmethod
    def from_string(cls, version_str):
        """
        Parse a pkg version from a string

        :param version_str:
        :return:
        """
        version_str = version_str.strip()

        pieces = version_str.rsplit(':', 1)
        if len(pieces) > 1:
            epoch = pieces.pop(0)
            try:
                i = int(epoch)
                if i < 0:
                    raise ValueError('Epoch is less than zero as an unsigned int')
            except:
                raise ValueError('Epoch must be an integer')
            if not pieces[0]:
                raise ValueError('Found only an epoch, must have version')
        else:
            epoch = None

        if epoch is None and ':' in pieces[0]:
            raise ValueError('Invalid string. Cannot contain a colon if no epoch specified')

        version_comps = pieces[0].rsplit('-', 1)
        if len(version_comps) < 2:
            version = version_comps[0]
            revision = '0'
        else:
            version = version_comps[0]
            revision = version_comps[1]

        if not epoch:
            epoch = 0

        return DpkgVersion(epoch=epoch, version=version, revision=revision)

    def __init__(self, epoch, version, revision):
        self.epoch = epoch
        self.version = version
        self.revision = revision

    def __cmp__(self, other):
        if not isinstance(other, DpkgVersion):
            raise TypeError('Can only compare other DpkVersion objects. Found: {}'.format(type(other)))

        if self.epoch > other.epoch:
            return 1
        if self.epoch < other.epoch:
            return 0

        ver_cmp = DpkgVersion._compare_version_str(self.version, other.version)
        if ver_cmp:
            return ver_cmp

        return DpkgVersion._compare_version_str(self.revision, other.revision)


    @staticmethod
    def _compare_version_str(ver_a, ver_b):
        """
        Compare single version string elements.

        A very close impl of the C code from the dpkg src. Probably a way to be more terse with python,
        but to avoid regressions, keeping it very close to the C code.

        :param ver_a:
        :param ver_b:
        :return: -1, 0, 1 is standard __cmp__ semantics
        """

        if ver_a is None:
            ver_a = ''
        if ver_b is None:
            ver_b = ''

        # Convert each to list of characters
        list_a = list(ver_a)
        list_b = list(ver_b)


        for i in range(max(len(list_a), len(list_b))):
            first_diff = 0
            while (list_a and not list_a[0].isdigit() or (list_b and not list_b[0].isdigit())):
                ac = DpkgVersion._order(list_a[0] if list_a else None)
                bc = DpkgVersion._order(list_b[0] if list_b else None)

                if ac != bc:
                    return ac - bc

                # Consume the chars
                list_a.pop(0)
                list_b.pop(0)

            while list_a and list_a[0] == '0':
                list_a.pop(0)

            while list_b and list_b[0] == '0':
                list_b.pop(0)

            while (list_a and list_a[0].isdigit()) and (list_b and list_b[0].isdigit()):
                if not first_diff:
                    first_diff = ord(list_a[0]) - ord(list_b[0])
                list_a.pop(0)
                list_b.pop(0)

            if list_a and list_a[0].isdigit():
                return 1

            if list_b and list_b[0].isdigit():
                return -1

            if first_diff:
                return first_diff

        return 0

    @staticmethod
    def _order(c):
        """
        Given a char, determine weight.

        :param c:
        :return:
        """
        if c is None:
            return 0

        if c.isdigit():
            return 0
        elif c.isalpha():
            return ord(c) #c[0])
        elif c == '~':
            return -1
        elif c:
            return ord(c) + 256
        else:
            return 0


def compare_versions(v1, op, v2):
    """
    Pure python impl of the dpkg version comparison code from: dpkg/lib/vercmp.c

    Returns standard boolean truth of op applied to v1 and v2, so if op == 'lt' and v1 < v2, return True.

    Splits the version string into number and non-number components and does a component-wise comparison.


    E.g.

    1.2.10 -> 1,2,10
    1.15.1 -> 1,15,1

    Thus 1.2.10 < 1.15.1.

    values for op:
    le, lt, eq, ne, ge, gt

    :param v1: version string
    :param op: string operator
    :param v2: version string
    :return:
    """

    if op not in compare_operators:
        raise ValueError('Invalid op, {}, requested. Valid values are: {}'.format(op, compare_operators.keys()))
    else:
        eval_fn = compare_operators[op]

    pkg1 = DpkgVersion.from_string(v1)
    pkg2 = DpkgVersion.from_string(v2)

    try:
        return eval_fn(pkg1.__cmp__(pkg2))
    except Exception as e:
        raise


if __name__ == '__main__':
    test_epoch = [
        ('1','1', 0),
        ('1:0', '0:10', 1),
        (),
        (),
        (),
    ]

    test_no_epoch = [
        ('1.01.1', '1.1.1', 'eq', False),
        ('1.01.1', '1.1.1', 'lt', True),
        ('1.01.1', '1.1.1', 'le', True),
        ('1.101.1', '1.100.1', 'eq', False),
        ('1.100a.1', '1.9a9.100', 'eq', False),
        ('1.100.1', '1.99.100', 'eq', False),
        ('1.100.1', '1.99.100', 'eq', False),
        ('1.100.1', '1.99.100', 'eq', False)
    ]


    for i in test_no_epoch:
        print('Testing: {}'.format(i))
        if not i[3] == compare_versions(i[0], i[2], i[1]):
            print('Mismatch!')
        else:
            print('Match!')

    print(compare_versions('1.900.1-debian1-2.4+deb8u3', 'lt', '1.900.1-5.1'))

