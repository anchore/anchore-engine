import sys


def generate_npms(user_id, image_id, count):
    result_rows = []
    latest = ""
    versions_json = '["2.1.0"]'
    licenses_json = '["MIT"]'
    origins_json = "[]"
    source_pkg = ""

    for c in range(count):
        path = "/usr/testing/somenpms/{}".format(c)
        path_hash = "abcdefg{}".format(c)
        name = "testnpm_{}".format(c)

        row = [
            user_id,
            image_id,
            path_hash,
            path,
            name,
            origins_json,
            source_pkg,
            licenses_json,
            versions_json,
            latest,
        ]

        result_rows.append("\t".join(row))

    return result_rows


if __name__ == "__main__":
    fname = sys.argv[1]
    row_count = int(sys.argv[2])
    user_id = sys.argv[3]
    image_id = sys.argv[4]

    print("Generating {} rows for image {}, {}".format(row_count, user_id, image_id))
    npms = generate_npms(user_id, image_id, row_count)

    with open(fname, "w") as f:
        print("Writing file {}".format(fname))
        f.write("\n".join(npms))
