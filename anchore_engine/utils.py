"""
Generic utilities
"""
import datetime
import decimal
import os
import platform
import re
import shlex
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from operator import itemgetter

from ijson import common as ijcommon
from ijson.backends import python as ijpython

from anchore_engine.subsys import logger

SANITIZE_CMD_ERROR_MESSAGE = "bad character in shell input"
PIPED_CMD_VALUE_ERROR_MESSAGE = "Piped command cannot be None or empty"

K_BYTES = 1024
M_BYTES = 1024 * K_BYTES
G_BYTES = 1024 * M_BYTES
T_BYTES = 1024 * G_BYTES

SIZE_UNITS = {"kb": K_BYTES, "mb": M_BYTES, "gb": G_BYTES, "tb": T_BYTES}

BYTES_REGEX = re.compile("^([0-9]+)([kmgt]b)?$")


def process_cve_status(old_cves_result=None, new_cves_result=None):
    """
    Returns the diff of two cve results. Only compares two valid results, if either is None or empty, will return empty.

    :param cve_record:
    :return: dict with diff results: {'added': [], 'updated': [], 'removed': []}
    """

    if not new_cves_result or not old_cves_result:
        return {}  # Nothing to do

    try:
        if "multi" in old_cves_result:
            old_cve_header = old_cves_result["multi"]["result"]["header"]
            old_cve_rows = old_cves_result["multi"]["result"]["rows"]
        else:
            # element 0 is the image id
            old_cve_header = old_cves_result[0]["result"]["header"]
            old_cve_rows = old_cves_result[0]["result"]["rows"]
    except:
        old_cve_header = None
        old_cve_rows = None

    try:
        if "multi" in new_cves_result:
            new_cve_header = new_cves_result["multi"]["result"]["header"]
            new_cve_rows = new_cves_result["multi"]["result"]["rows"]
        else:
            # element 0 is the image id
            new_cve_header = new_cves_result[0]["result"]["header"]
            new_cve_rows = new_cves_result[0]["result"]["rows"]
    except:
        new_cve_header = None
        new_cve_rows = None

    summary_elements = [
        "CVE_ID",
        "Severity",
        "Vulnerable_Package",
        "Fix_Available",
        "URL",
        "Package_Name",
        "Package_Version",
        "Package_Type",
        "Feed",
        "Feed_Group",
    ]

    if new_cve_rows is None or old_cve_rows is None:
        return {}

    new_cves = pivot_rows_to_keys(
        new_cve_header,
        new_cve_rows,
        key_names=["CVE_ID", "Vulnerable_Package"],
        whitelist_headers=summary_elements,
    )
    old_cves = pivot_rows_to_keys(
        old_cve_header,
        old_cve_rows,
        key_names=["CVE_ID", "Vulnerable_Package"],
        whitelist_headers=summary_elements,
    )
    diff = item_diffs(old_cves, new_cves)

    return diff


def item_diffs(old_items=None, new_items=None):
    """
    Given previous cve-scan output and new cve-scan output for the same image, return a diff as a map.
    Keys:
    {
        'added': [],
        'removed': [],
        'updated': []
    }

    :param old_cves: mapped cve results (from map_rows() result) from previous value
    :param new_cves: mapped cve results (from map_rows() result) from current_value
    :return: dictionary object with results
    """

    if not old_items:
        old_items = {}

    if not new_items:
        new_items = {}

    new_ids = set(new_items.keys())
    old_ids = set(old_items.keys())
    added = [new_items[x] for x in new_ids.difference(old_ids)]
    removed = [old_items[x] for x in old_ids.difference(new_ids)]
    intersected_ids = new_ids.intersection(old_ids)
    updated = [
        new_items[x]
        for x in [x for x in intersected_ids if new_items[x] != old_items[x]]
    ]

    return {"added": added, "removed": removed, "updated": updated}


def list_to_map(item_list, key_name):
    """
    Given a list of dicts/objects return a dict mapping item[key_name] -> item

    :param item_list:
    :param key_name:
    :return:
    """

    return {x.pop(key_name): x for x in item_list}


def map_rows(header_list, row_list):
    """
    :param header_list: list of names ordered to match row data, provides names for each row
    :param row_list: list of row tuples/lists with each tuple/list in same order as header_list
    :return: list of dicts with named values instead of tuples
    """

    header_map = {v: header_list.index(v) for v in header_list}
    mapped = [{key: item[header_map[key]] for key in header_map} for item in row_list]
    return mapped


def pivot_rows_to_keys(header_list, row_list, key_names=[], whitelist_headers=None):
    """
    Slightly more direct converter for header,row combo into a dict of objects

    :param header_list:
    :param row_list:
    :param key_name:
    :return:
    """
    header_map = {
        v: header_list.index(v)
        for v in [
            x
            for x in header_list
            if not whitelist_headers or x in whitelist_headers or x in key_names
        ]
    }

    key_idxs = []
    for key_name in key_names:
        key_idxs.append(header_map[key_name])

    # key_idx = header_map[key_name]
    # return {"{}{}".format(x[key_idx],x[keya_idx]): {k: x[v] for k, v in list(header_map.items())} for x in row_list}

    return {
        ":".join(itemgetter(*key_idxs)(x)): {
            k: x[v] for k, v in list(header_map.items())
        }
        for x in row_list
    }


def filter_record_keys(record_list, whitelist_keys):
    """
    Filter the list records to remove verbose entries and make it suitable for notification format
    :param record_dict: dict containing values to process
    :param whitelist_keys: keys to leave in the record dicts
    :return: a new list with dicts that only contain the whitelisted elements
    """

    filtered = [
        {k: v for k, v in [y for y in list(x.items()) if y[0] in whitelist_keys]}
        for x in record_list
    ]
    return filtered


def run_sanitize(cmd_list):
    def shellcheck(x):
        if not re.search("[;&<>]", x):
            return x
        else:
            raise Exception(SANITIZE_CMD_ERROR_MESSAGE)

    return [x for x in cmd_list if shellcheck(x)]


def run_command_list_with_piped_input(
    cmd_list,
    input_data,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    stdin=subprocess.PIPE,
    **kwargs
):
    """
    Pipe the input data to the command list and run it with optional environment and return a tuple (rc, stdout_str, stderr_str)

    :param cmd_list: list of command e.g. ['ls', '/tmp']
    :param input_data: string or bytes to be piped to cmd_list
    :param stdin:
    :param stdout:
    :param stderr:
    :return: tuple (rc_int, stdout_str, stderr_str)
    """
    try:
        input_data = input_data.encode("utf-8")
    except AttributeError:
        # it is a str already, no need to encode
        pass

    cmd_list = run_sanitize(cmd_list)
    pipes = subprocess.Popen(
        cmd_list, **dict(stdout=stdout, stderr=stderr, stdin=stdin, **kwargs)
    )
    stdout_result, stderr_result = pipes.communicate(input=input_data)

    return pipes.returncode, stdout_result, stderr_result


def run_command_list(
    cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs
):
    """
    Run a command from a list with optional environment and return a tuple (rc, stdout_str, stderr_str)
    :param cmd_list: list of command e.g. ['ls', '/tmp']
    :param env: dict of env vars for the environment if desired. will replace normal env, not augment
    :return: tuple (rc_int, stdout_str, stderr_str)
    """

    cmd_list = run_sanitize(cmd_list)
    pipes = subprocess.Popen(cmd_list, **dict(stdout=stdout, stderr=stderr, **kwargs))
    stdout_result, stderr_result = pipes.communicate()

    return pipes.returncode, stdout_result, stderr_result


def run_check(cmd, input_data=None, log_level="debug", **kwargs):
    """
    Run a command (input required to be a list), log the output, and raise an
    exception if a non-zero exit status code is returned.
    """
    cmd = run_sanitize(cmd)

    try:
        if input_data is not None:
            logger.debug("running cmd: %s with piped input", " ".join(cmd))
            code, stdout, stderr = run_command_list_with_piped_input(
                cmd, input_data, **kwargs
            )
        else:
            logger.debug("running cmd: %s", " ".join(cmd))
            code, stdout, stderr = run_command_list(cmd, **kwargs)
    except FileNotFoundError:
        msg = "unable to run command. Executable does not exist or not availabe in path"
        raise CommandException(cmd, 1, "", "", msg=msg)

    try:
        stdout = stdout.decode("utf-8")
        stderr = stderr.decode("utf-8")
    except AttributeError:
        # it is a str already, no need to decode
        pass

    stdout_stream = stdout.splitlines()
    stderr_stream = stderr.splitlines()

    if log_level == "spew":
        # Some commands (like grype scanning) will generate enough output here that we
        # need to try to limit the impact of debug logging on system performance
        for line in stdout_stream:
            logger.spew("stdout: %s" % line)  # safe formatting not available for spew
        for line in stderr_stream:
            logger.spew("stderr: %s" % line)
    else:  # Always log stdout and stderr as debug, unless spew is specified
        for line in stdout_stream:
            logger.debug("stdout: %s", line)
        for line in stderr_stream:
            logger.debug("stderr: %s", line)

    if code != 0:
        # When non-zero exit status returns, log stderr as error, but only when
        # the log level is higher (lower in Engine's interpretation) than debug.
        # XXX: engine mangles the logger, so this way of checking the level is
        # non-standard. This line should be:
        #     if logger.level > logging.debug:
        if logger.log_level < logger.log_level_map["DEBUG"]:
            for line in stderr_stream:
                logger.error(line)
        raise CommandException(cmd, code, stdout, stderr)

    return stdout, stderr


def run_command(cmdstr, **kwargs):
    return run_command_list(shlex.split(cmdstr), **kwargs)


def get_threadbased_id(guarantee_uniq=False):
    """
    Returns a string for use with acquire() calls optionally. Constructs a consistent id from the platform node, process_id and thread_id

    :param guarantee_uniq: bool to have the id generate a uuid suffix to guarantee uniqeness between invocations even in the same thread
    :return: string
    """

    return "{}:{}:{}:{}".format(
        platform.node(),
        os.getpid(),
        str(threading.get_ident()),
        uuid.uuid4().hex if guarantee_uniq else "",
    )


class AnchoreException(Exception):
    def to_dict(self):
        return {
            self.__class__.__name__: dict(
                (key, value)
                for key, value in vars(self).items()
                if not key.startswith("_")
            )
        }


class CommandException(Exception):
    """
    An exception raised when subprocess.Popen calls have non-zero exit status.
    Capture useful information as part of the exception raised
    """

    def __init__(self, cmd, code, stdout, stderr, msg=None):
        self.msg = msg or "Non-zero exit status code when running subprocess"
        self.cmd = " ".join(cmd) if isinstance(cmd, list) else cmd
        self.code = code
        self.stderr = stderr
        self.stdout = stdout

    def __repr__(self):
        return "{}: cmd={}, rc={}".format(self.msg, self.cmd, self.code)

    def __str__(self):
        return "{}: cmd={}, rc={}".format(self.msg, self.cmd, self.code)


def ensure_bytes(obj):
    return obj.encode("utf-8") if type(obj) != bytes else obj


def ensure_str(obj):
    return str(obj, "utf-8") if type(obj) != str else obj


rfc3339_date_fmt = "%Y-%m-%dT%H:%M:%SZ"
rfc3339_date_input_fmts = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S:%fZ",
]


def rfc3339str_to_epoch(rfc3339_str):
    return int(rfc3339str_to_datetime(rfc3339_str).timestamp())


def rfc3339str_to_datetime(rfc3339_str):
    """
    Convert the rfc3339 formatted string (UTC only) to a datatime object with tzinfo explicitly set to utc. Raises an exception if the parsing fails.

    :param rfc3339_str:
    :return:
    """

    ret = None
    for fmt in rfc3339_date_input_fmts:
        try:
            ret = datetime.datetime.strptime(rfc3339_str, fmt)
            # Force this since the formats we support are all utc formats, to support non-utc
            if ret.tzinfo is None:
                ret = ret.replace(tzinfo=datetime.timezone.utc)
            continue
        except:
            pass

    if ret is None:
        raise Exception(
            "could not convert input value ({}) into datetime using formats in {}".format(
                rfc3339_str, rfc3339_date_input_fmts
            )
        )

    return ret


def datetime_to_rfc3339(dt_obj):
    """
    Simple utility function. Expects a UTC input, does no tz conversion

    :param dt_obj:
    :return:
    """

    return dt_obj.strftime(rfc3339_date_fmt)


def epoch_to_rfc3339(epoch_int):
    """
    Convert an epoch int value to a RFC3339 datetime string

    :param epoch_int:
    :return:
    """
    return datetime_to_rfc3339(datetime.datetime.utcfromtimestamp(epoch_int))


def convert_bytes_size(size_str):
    """
    Converts a size string to an int. Allows trailing units

    e.g. "10" -> 10, "1kb" -> 1024, "1gb" -> 1024*1024*1024
    :param size_str:
    :return:
    """

    m = BYTES_REGEX.fullmatch(size_str.lower())
    if m:
        number = int(m.group(1))

        if m.group(2) is not None:
            unit = m.group(2)
            conversion = SIZE_UNITS.get(unit)
            if conversion:
                return conversion * number
        return number
    else:
        raise ValueError("Invalid size string: {}".format(size_str))


CPE_SPECIAL_CHAR_ENCODER = {
    "!": "%21",
    '"': "%22",
    "#": "%23",
    "$": "%24",
    "%": "%25",
    "&": "%26",
    "'": "%27",
    "(": "%28",
    ")": "%29",
    "*": "%2a",
    "+": "%2b",
    ",": "%2c",
    # '-': '-',  # not affected by transformation between formatted string and uri, only impacts wfn
    # '.': '.',  # not affected by transformation between formatted string and uri, only impacts wfn
    "/": "%2f",
    ":": "%3a",
    ";": "%3b",
    "<": "%3c",
    "=": "%3d",
    ">": "%3e",
    "?": "%3f",
    "@": "%40",
    "[": "%5b",
    "\\": "%5c",
    "]": "%5d",
    "^": "%5e",
    "`": "%60",
    "{": "%7b",
    "|": "%7c",
    "}": "%7d",
    "~": "%7e",
}


class CPE(object):
    """
    A helper class for converting CPE 2.3 formatted string into CPE 2.2 URI and matching CPE 2.3 formatted strings
    """

    def __init__(
        self,
        part=None,
        vendor=None,
        product=None,
        version=None,
        update=None,
        edition=None,
        language=None,
        sw_edition=None,
        target_sw=None,
        target_hw=None,
        other=None,
    ):
        self.part = part
        self.vendor = vendor
        self.product = product
        self.version = version
        self.update = update
        self.edition = edition
        self.language = language
        self.sw_edition = sw_edition
        self.target_sw = target_sw
        self.target_hw = target_hw
        self.other = other

    def __hash__(self):
        return hash(
            (
                self.part,
                self.vendor,
                self.product,
                self.version,
                self.update,
                self.edition,
                self.language,
                self.sw_edition,
                self.target_sw,
                self.target_hw,
                self.other,
            )
        )

    def __eq__(self, other):
        return other and self == other

    def __repr__(self):
        return "CPE: part={}, vendor={}, product={}, version={}, update={}, edition={}, language={}, sw_edition={}, target_sw={}, target_hw={}, other={}".format(
            self.part,
            self.vendor,
            self.product,
            self.version,
            self.update,
            self.edition,
            self.language,
            self.sw_edition,
            self.target_sw,
            self.target_hw,
            self.other,
        )

    def copy(self):
        return CPE(
            part=self.part,
            vendor=self.vendor,
            product=self.product,
            version=self.version,
            update=self.update,
            edition=self.edition,
            language=self.language,
            sw_edition=self.sw_edition,
            target_sw=self.target_sw,
            target_hw=self.target_hw,
            other=self.other,
        )

    @staticmethod
    def from_cpe23_fs(cpe23_fs):
        """
        Takes a CPE 2.3 formatted string and returns a CPE object. This is the only supported method to create an instance of this class

        This is not entirely true to the spec, it does not unbind all the elements as wfn representation is not used.
        All of unbinding logic is concentrated in the conversion from wfn to uri format in as_cpe22_uri()

        :param cpe23_fs: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        :return:
        """

        cpe_parts = cpe23_fs.split(":")

        if cpe_parts and len(cpe_parts) == 13:
            return CPE(
                part=cpe_parts[2],
                vendor=cpe_parts[3],
                product=cpe_parts[4],
                version=cpe_parts[5],
                update=cpe_parts[6],
                edition=cpe_parts[7],
                language=cpe_parts[8],
                sw_edition=cpe_parts[9],
                target_sw=cpe_parts[10],
                target_hw=cpe_parts[11],
                other=cpe_parts[12],
            )
        elif len(cpe_parts) > 13:
            # logger.debug('{} did not split nicely into 13 parts'.format(cpe23_fs))

            adjusted_cpe_parts = []
            counter = 1

            # start from the third element in the list and iterate through the penultimate element
            while counter < len(cpe_parts) - 1:
                counter += 1
                part = cpe_parts[counter]

                # if the element ends with a '\', good chance its an escape for ':', concatenate the elements together
                if part.endswith("\\"):
                    new_part = part

                    while counter < len(cpe_parts) - 1:
                        counter += 1
                        part = cpe_parts[counter]
                        new_part += ":" + part

                        if part.endswith("\\"):
                            continue
                        else:
                            break

                    adjusted_cpe_parts.append(new_part)
                else:
                    adjusted_cpe_parts.append(part)

            if len(adjusted_cpe_parts) == 11:
                # logger.debug('Adjusted cpe components: {}'.format(adjusted_cpe_parts))
                return CPE(
                    part=adjusted_cpe_parts[0],
                    vendor=adjusted_cpe_parts[1],
                    product=adjusted_cpe_parts[2],
                    version=adjusted_cpe_parts[3],
                    update=adjusted_cpe_parts[4],
                    edition=adjusted_cpe_parts[5],
                    language=adjusted_cpe_parts[6],
                    sw_edition=adjusted_cpe_parts[7],
                    target_sw=adjusted_cpe_parts[8],
                    target_hw=adjusted_cpe_parts[9],
                    other=adjusted_cpe_parts[10],
                )
            else:
                raise Exception(
                    "Cannot convert cpe 2.3 formatted string {} into wfn".format(
                        cpe23_fs
                    )
                )
        else:
            raise Exception(
                "Invalid cpe 2.3 formatted string {} Splitting with : delimiter resulted in less than 13 elements".format(
                    cpe23_fs
                )
            )

    def as_cpe23_fs(self):
        return "cpe:2.3:{}".format(
            ":".join(
                [
                    self.part,
                    self.vendor,
                    self.product,
                    self.version,
                    self.update,
                    self.edition,
                    self.language,
                    self.sw_edition,
                    self.target_sw,
                    self.target_hw,
                    self.other,
                ]
            )
        )

    def update_version(self, version):
        """
        Helper method for escaping the
        Ensures that resulting version is CPE 2.3 formatted string compliant, this is necessary for as_cpe22_uri() to do its thing
        affected version data in nvd json data which is usually unescaped. Converts the supplied version

        :param version:
        :return:
        """
        self.version = CPE.escape_for_cpe23_fs(version)

    @staticmethod
    def escape_for_cpe23_fs(element):
        """
        Helper method for escaping special characters as per the CPE 2.3 formatted string spec

        :param element:
        :return: escaped element string as per CPE 2.3 formatted string spec
        """

        if not isinstance(element, str):
            raise Exception("Value to be escaped is not a string")

        if element in ["*", "-", ""]:  # let these pass through as they are
            return element
        elif any(char in CPE_SPECIAL_CHAR_ENCODER.keys() for char in element):
            new_element = str()
            pos = 0
            while pos < len(element):
                char = element[pos]

                if (
                    char == "\\"
                ):  # this might be an escape character, check to see if the next character requires escape
                    pos += 1
                    if pos < len(element):
                        n_char = element[pos]
                        if (
                            n_char in CPE_SPECIAL_CHAR_ENCODER
                        ):  # definitely an escaped sequence, preserve it as it is
                            new_element += char + n_char
                        else:  # just a \ that needs to be escaped
                            new_element += "\\" + char + n_char
                    else:  # last char is unescaped \, just add an escape
                        new_element += "\\" + char
                elif char in CPE_SPECIAL_CHAR_ENCODER:
                    new_element += "\\" + char
                else:
                    new_element += char

                pos += 1

            return new_element
        else:
            return element

    @staticmethod
    def bind_for_cpe22_uri(element):
        if not isinstance(element, str):
            raise Exception("Value to be bound in URI format is not a string")

        if element == "*":
            return ""
        elif element in ["-", ""]:
            return element
        else:
            result = str()
            pos = -1
            while pos < (len(element) - 1):
                pos += 1
                char = element[pos]
                if char == "\\":  # an escaped character, percent encode it if possible
                    if pos != (
                        len(element) - 1
                    ):  # check the next character and transform into percent encoded string
                        pos += 1
                        n_char = element[pos]
                        encoded = CPE_SPECIAL_CHAR_ENCODER.get(n_char, None)
                        if encoded:
                            result += encoded
                        else:  # no encoding found, let it go through as it is
                            logger.warn(
                                "No encoding found for {}{}".format(char, n_char)
                            )
                            result += char + n_char
                    else:  # this is the last char, nothing to percent encode
                        logger.warn(
                            "{} is the last char, skipping percent encoded transformation".format(
                                char
                            )
                        )
                        result += char
                elif char == "?":  # bind the unescaped ? to %01
                    result += "%01"
                elif char == "*":  # bind the unescaped * to %02
                    result += "%02"
                else:
                    result += char

            return result

    def as_cpe22_uri(self):
        """
        Transforms this CPE object into a CPE 2.2 URI. Based on the specification in https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf

        :return: CPE 2.2 URI string
        """

        # part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        # 0    1      2       3       4      5       6        7          8         9         10
        # |-------------cpe 2.2 attributes-----------        |------------new in cpe 2.3----------|

        e = CPE.bind_for_cpe22_uri(self.edition)
        sw_e = CPE.bind_for_cpe22_uri(self.sw_edition)
        t_sw = CPE.bind_for_cpe22_uri(self.target_sw)
        t_hw = CPE.bind_for_cpe22_uri(self.target_hw)
        o = CPE.bind_for_cpe22_uri(self.other)

        if sw_e or t_sw or t_hw or o:
            edition = "~{}~{}~{}~{}~{}".format(e, sw_e, t_sw, t_hw, o)
        else:
            edition = e

        uri_parts = [
            "cpe",
            "/" + self.part,
            CPE.bind_for_cpe22_uri(self.vendor),
            CPE.bind_for_cpe22_uri(self.product),
            CPE.bind_for_cpe22_uri(self.version),
            CPE.bind_for_cpe22_uri(self.update),
            edition,
            CPE.bind_for_cpe22_uri(self.language),
        ]

        uri = ":".join(uri_parts)
        uri = uri.strip(":")  # remove any trailing :

        return uri

    def is_match(self, other_cpe):
        """
        This is a very limited implementation of cpe matching. other_cpe is a wildcard ridden base cpe used by range descriptors
        other_cpe checked against this cpe for an exact match of part and vendor.
        For all the remaining components a match is positive if the other cpe is an exact match or contains the wild char

        :param other_cpe:
        :return:
        """
        if not isinstance(other_cpe, CPE):
            return False

        if self.part == other_cpe.part and self.vendor == other_cpe.vendor:

            if other_cpe.product not in ["*", self.product]:
                return False
            if other_cpe.version not in ["*", self.version]:
                return False
            if other_cpe.update not in ["*", self.update]:
                return False
            if other_cpe.edition not in ["*", self.edition]:
                return False
            if other_cpe.language not in ["*", self.language]:
                return False
            if other_cpe.sw_edition not in ["*", self.sw_edition]:
                return False
            if other_cpe.target_sw not in ["*", self.target_sw]:
                return False
            if other_cpe.target_hw not in ["*", self.target_hw]:
                return False
            if other_cpe.other not in ["*", self.other]:
                return False

            return True
        else:
            return False


@contextmanager
def timer(label, log_level="debug"):
    t = time.time()
    try:
        yield
    finally:
        log_level = log_level.lower()
        if log_level == "info":
            logger.info(
                "Execution of {} took: {} seconds".format(label, time.time() - t)
            )
        elif log_level == "warn":
            logger.warn(
                "Execution of {} took: {} seconds".format(label, time.time() - t)
            )
        elif log_level == "spew":
            logger.spew(
                "Execution of {} took: {} seconds".format(label, time.time() - t)
            )
        else:
            logger.debug(
                "Execution of {} took: {} seconds".format(label, time.time() - t)
            )


# Generally we're not dealing with high precision floats in feed data, so this shouldn't result in any loss of precision
def ijson_decimal_to_float(event):
    """
    Event handler for use with ijson parsers to output floats instead of Decimals for better json serializability downstream.

    :param event:
    :return:
    """
    if event[1] == "number" and isinstance(event[2], decimal.Decimal):
        return event[0], event[1], float(event[2])
    else:
        return event


def mapped_parser_item_iterator(input_stream, item_path):
    """
    Boilerplate function to setup the event mapper to ensure floats instead of decimals for use with ijson

    :param input_stream:
    :param item_path:
    :return:
    """
    events = map(ijson_decimal_to_float, ijpython.parse(input_stream))
    return ijcommon.items(events, item_path)


def bytes_to_mb(value, round_to=None):
    mb = value / M_BYTES
    if round_to:
        mb = round(mb, round_to)

    return mb
