import sys


def generate_npms(user_id, image_id, count, use_seq=False):
    result_rows = []
    latest = "2.1.0"
    versions_json = '["2.1.0"]'
    licenses_json = '["MIT"]'
    origins_json = "[]"
    source_pkg = ""
    seq = 0

    for c in range(count):
        path = "/usr/testing/somegems/{}".format(c)
        path_hash = "abcdefg{}".format(c)
        name = "testgem_{}".format(c)
        files_json = '["somefile", "somefile2"]'

        if use_seq:
            row = [
                user_id,
                image_id,
                path_hash,
                path,
                name,
                files_json,
                origins_json,
                source_pkg,
                licenses_json,
                versions_json,
                latest,
                str(seq),
            ]
        else:
            row = [
                user_id,
                image_id,
                path_hash,
                path,
                name,
                files_json,
                origins_json,
                source_pkg,
                licenses_json,
                versions_json,
                latest,
            ]

        seq += 1
        result_rows.append("\t".join(row))

    return result_rows


if __name__ == "__main__":
    fname = sys.argv[1]
    row_count = int(sys.argv[2])
    user_id = sys.argv[3]
    image_id = sys.argv[4]
    if len(sys.argv) == 6:
        use_seq = sys.argv[5]
    else:
        use_seq = False

    print("Generating {} rows for image {}, {}".format(row_count, user_id, image_id))
    npms = generate_npms(user_id, image_id, row_count, use_seq)

    with open(fname, "w") as f:
        print("Writing file {}".format(fname))
        f.write("\n".join(npms))
