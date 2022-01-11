import hashlib
import pyinstrument
import cProfile
import pstats
from memory_profiler import profile


import json
import ujson
import orjson


enterprise_sbom = "/Users/rbrady/anchore_enterprise.sbom"


def profile_n(func):
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


def get_file_hash(filepath: str) -> str:
    """computes a sha256 hash of a given file
    This function utilizes a block approach to computing the hash to support large files
    @param filepath: path to a file on disk
    @return: a string representing a sha256 hash, "588942a6896efa853a53acbc24fcf87fa5651e6d66eebe549037d0822368a37a"
    """
    with open(filepath, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            hashlib.sha256().update(byte_block)
        return hashlib.sha256().hexdigest()


def get_file_hash2(filepath: str) -> str:
    """computes a sha256 hash of a given file
    This function utilizes a block approach to computing the hash to support large files
    @param filepath: path to a file on disk
    @return: a string representing a sha256 hash, "588942a6896efa853a53acbc24fcf87fa5651e6d66eebe549037d0822368a37a"
    """
    retval = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            retval.update(byte_block)
        return retval.hexdigest()


def modify_bytes(filepath: str) -> str:
    """computes a sha256 hash of a given file
    This function utilizes a block approach to computing the hash to support large files
    @param filepath: path to a file on disk
    @return: a string representing a sha256 hash, "588942a6896efa853a53acbc24fcf87fa5651e6d66eebe549037d0822368a37a"
    """
    retval = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            retval.update(byte_block)
        return retval.hexdigest()


def ensure_bytes(obj):
    return obj.encode("utf-8") if type(obj) != bytes else obj


def ensure_str(obj):
    return str(obj, "utf-8") if type(obj) != str else obj


@profile
def hash_all(filepath):
    input_bytes = None
    # open a file
    with open(filepath, "rb") as input_file:
        input_bytes = input_file.read()

    # input_bytes simulates the
    # hash the file * inspect CPU / mem
    hv = hashlib.sha256(input_bytes)
    return hv.hexdigest()


@profile
def bytes_with_additions(filepath):
    input_bytes = None
    # open a file
    with open(filepath, "rb") as input_file:
        input_bytes = input_file.read()

    # x2 increase
    # foo = b"".join([b'{"document": ', input_bytes, b"}"])

    retval = bytearray(b'{"document":')
    retval += input_bytes
    retval += b"}"


@profile
def bytes_only(filepath):
    input_bytes = None
    # open a file
    with open(filepath, "rb") as input_file:
        input_bytes = input_file.read()

    foo = input_bytes


@profile
def hash_incremental(filepath):
    hv = get_file_hash2(filepath)
    return hv


def read_file(filepath: str):
    with open(filepath, "r") as fd:
        return fd.read()


@profile
def parse_json_json_loads(contents: str):
    result = json.loads(contents)
    return result


@profile
def parse_json_ujson_loads(contents: str):
    result = ujson.loads(contents)
    return result


@profile
def parse_json_orjson_loads(contents: str):
    result = orjson.loads(contents)
    return result


@profile
def parse_json_json_dumps(contents: dict):
    result = json.dumps(contents)
    return result


@profile
def parse_json_ujson_dumps(contents: dict):
    result = ujson.dumps(contents)
    return result


@profile
def parse_json_orjson_dumps(contents: dict):
    result = orjson.dumps(contents)
    return result


def test_json_json():
    contents = read_file(enterprise_sbom)
    json_data = parse_json_json_loads(contents)
    json_contents = parse_json_json_dumps(json_data)


def test_json_ujson():
    contents = read_file(enterprise_sbom)
    ujson_data = parse_json_ujson_loads(contents)
    ujson_contents = parse_json_ujson_dumps(ujson_data)


def test_json_orjson():
    contents = read_file(enterprise_sbom)
    orjson_data = parse_json_orjson_loads(contents)
    orjson_contents = parse_json_orjson_dumps(orjson_data)


def test_nested_async_strategy():
    """The question is are there specific strategies useful for grouping asnyc tasks in a nested state"""
    # simulate subprocess communication
    # simulate download
    # simulate process
    # simulate upload content with results from process
    # simulate looping get request with a wait "wait_for_image"
    # simulate get vulns
    # simulate get policy
    return


def main():
    # h1 = hash_incremental(enterprise_sbom)
    # h2 = hash_all(enterprise_sbom)
    # print(h1)
    # print(h2)
    # bytes_with_additions(enterprise_sbom)
    # bytes_only(enterprise_sbom)
    # test_json_json()
    # test_json_ujson()
    # test_json_orjson()


# importing a 50mb json file
"""
document (bytes)
256hash(document)

convert bytes to string -> new string created
get json from it, but adding an addition key hierarchy {'document': data} -> copy to dict

turn json back to bytes -> new bytes obj created
store to object store

how we can impact this:


store the bytes to a temporary file
do the hash against the file incrementally

add prefix and suffix bytes to the bytes object

read edited temp file as bytes and store to obj_manager
delete the temporary file

"""


if __name__ == "__main__":
    main()
