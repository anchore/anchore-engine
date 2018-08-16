"""
RPM utilities with no binary dependencies on rpm or rpmUtil.

"""


def parse_version(rpm_version):
    """
    Return a tuple from the given version string.
    
    :param rpm_version: 
    :return: 
    """
    return rpm_version.split('-')


def split_rpm_filename(rpm_filename):
    """
    Parse the components of an rpm filename and return them as a tuple: (name, version, release, epoch, arch)

    foo-1.0-1.x86_64.rpm -> foo, 1.0, 1, '', x86_64
    1:bar-9-123a.ia64.rpm -> bar, 9, 123a, 1, ia64

    :param rpm_filename: a string filename (not path) of an rpm file
    :returns: a tuple of the constituent parts compliant with RPM spec.
    """

    components = rpm_filename.rsplit('.rpm', 1)[0].rsplit('.', 1)
    arch = components.pop()

    rel_comp = components[0].rsplit('-', 2)
    release = rel_comp.pop()

    # Version
    version = rel_comp.pop()

    # Epoch
    epoch_comp = rel_comp[0].split(':', 1) if rel_comp else []
    if len(epoch_comp) == 1:
        epoch = ''
        name = epoch_comp[0]
    elif len(epoch_comp) > 1:
        epoch = epoch_comp[0]
        name = epoch_comp[1]
    else:
        epoch = None
        name = None

    return name, version, release, epoch, arch


def compare_versions(pkg_a, ver_a, pkg_b, ver_b):
    """
    Compare pkg and versions using rpm file name rules. Follows standard __cmp__ semantics of -1 iff a < b, 0 iff a == b, 1 iff a > b
    
    :param pkg_a: 
    :param ver_a: 
    :param pkg_b: 
    :param ver_b: 
    :return: 
    """
    if pkg_a == pkg_b and ver_a == ver_b:
        return 0
    file_b = pkg_b + "-" + ver_b + ".arch.rpm"
    file_a = pkg_a + "-" + ver_a + ".arch.rpm"
    (n1, v1, r1, e1, a1) = split_rpm_filename(file_a)
    (n2, v2, r2, e2, a2) = split_rpm_filename(file_b)

    if compare_labels(('1', v1, r1), ('1', v2, r2)) < 0:
        return -1
    else:
        return 1


def compare_labels(evr_1, evr_2):
    """
    Compare the EVR labels (epoch, version, release).    
    :param evr_1: 
    :param evr_2: 
    :return: 
    """
    epoch_1, ver_1, rel_1 = evr_1
    epoch_2, ver_2, rel_2 = evr_2

    if epoch_1 > epoch_2:
        return 1
    if epoch_1 < epoch_2:
        return -1

    cmp_result = rpm_ver_cmp(ver_1, ver_2)

    if cmp_result != 0:
        return cmp_result

    return rpm_ver_cmp(rel_1, rel_2)


def rpm_ver_cmp(a, b):
    """
    A translation of the RPM lib's C code for version compare rpmvercmp in lib/rpmvercmp.c into pure python with
    no external 
    
    compare alpha and numeric segments of two versions
    return 1: a is newer than b
        0: a and b are the same version
       -1: b is newer than a
    """

    # Convert to a list of single chars
    l_a = list(a.strip())
    l_b = list(b.strip())
    is_num = False

    # loop through each version segment of str1 and str2 and compare them
    while l_a and l_b:
        # Skip any whitespace preceding
        while l_a and not l_a[0].isalnum():
            l_a.pop(0)
        while l_b and not l_b[0].isalnum():
            l_b.pop(0)

        # If we ran to the end of either, we are finished with the loop
        if not (l_a and l_b):
            break

        # Get the next numeric or alpha segment to compare. Must get similar types from both strings.
        # This is a greedy consumption from the src string. so l_a/l_b will be truncated from the front to
        # construct the a/b_seg
        is_num, a_seg = greedy_find_block(l_a)
        b_is_num, b_seg = greedy_find_block(l_b, is_num)

        # this cannot happen, as we previously tested to make sure that
        # the first string has a non-null segment
        # if (one == str1) return -1;     # arbitrary
        if l_a == a_seg:
            raise Exception('Encountered null segment in str. Unexpected')
            # return -1 # Arbitrary per C impl

        # take care of the case where the two version segments are
        # different types: one numeric, the other alpha (i.e. empty)
        # numeric segments are always newer than alpha segments
        # XXX See patch #60884 (and details) from bugzilla #50977.
        # if (two == str2) return (isnum ? 1 : -1);
        if l_b == b_seg:
            return 1 if is_num else -1

        a_seg = ''.join(a_seg)
        b_seg = ''.join(b_seg)

        if is_num:
            # Strip leading zeros since this is a numeric comparison
            a_seg = a_seg.lstrip('0')
            b_seg = b_seg.lstrip('0')

            # whichever number has more digits wins
            if len(a_seg) > len(b_seg):
                return 1
            elif len(a_seg) < len(b_seg):
                return -1

        # String compare of the segments, covers both numeric and non since they are same length if numeric
        if a_seg > b_seg:
            return 1
        elif a_seg < b_seg:
            return -1

    # this catches the case where all numeric and alpha segments have
    # compared identically but the segment separating characters were
    # different

    # zhill - note the original comparison: if ((!*one) && (!*two)) return 0;
    if not l_a and not l_b:
        return 0

    # whichever version still has characters left over wins
    if not l_a:
        return -1
    else:
        return 1


def greedy_find_block(list_str, expected_digit=None):
    """
    Scan the string and return the substring, index, and type of the next block.
    A block is defined as a contiguous set of numeric or alpha characters. The point at which the string
    converts from one to another is the edge of the block.
    
    Will pop elements of the list to consume them during processing
    
    :param list_str: a string in list form: ['a', 'c', 'd', '1', '0', '.']
    :return: (bool, list) tuple, where bool is isdigit() for first char of string
    """

    # True for digits, false for alpha
    chr_type = list_str[0].isdigit()
    if expected_digit is not None and expected_digit != chr_type:
        # An explicit type request and the head of this string doesn't match, so return the other type and an empty list
        return expected_digit, []

    result = []
    while list_str and chr_type == list_str[0].isdigit():
        result += list_str.pop(0)

    return chr_type, result

if __name__ == '__main__':
    import sys
    print((compare_versions('pkg1', sys.argv[1],'pkg1', sys.argv[2])))




