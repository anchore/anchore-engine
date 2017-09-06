"""
Generic utilities
"""
import json

def process_cve_status(old_cves_result=None, new_cves_result=None):
    """
    Returns the diff of two cve results. Only compares two valid results, if either is None or empty, will return empty.

    :param cve_record:
    :return: dict with diff results: {'added': [], 'updated': [], 'removed': []}
    """

    if not new_cves_result or not old_cves_result:
        return {} # Nothing to do

    try:
        if 'multi' in old_cves_result:
            old_cve_header = old_cves_result['multi']['result']['header']
            old_cve_rows = old_cves_result['multi']['result']['rows']
        else:
            # element 0 is the image id
            old_cve_header = old_cves_result[0]['result']['header']
            old_cve_rows = old_cves_result[0]['result']['rows']
    except:
        old_cve_header = None
        old_cve_rows = None

    try:
        if 'multi' in new_cves_result:
            new_cve_header = new_cves_result['multi']['result']['header']
            new_cve_rows = new_cves_result['multi']['result']['rows']
        else:
            # element 0 is the image id
            new_cve_header = new_cves_result[0]['result']['header']
            new_cve_rows = new_cves_result[0]['result']['rows']
    except:
        new_cve_header = None
        new_cve_rows = None

    summary_elements = [
        "CVE_ID",
        "Severity",
        "Vulnerable_Package",
        "Fix_Available",
        "URL"
    ]

    if new_cve_rows is None or old_cve_rows is None:
        return {}

    new_cves = pivot_rows_to_keys(new_cve_header, new_cve_rows, key_name='CVE_ID',
                                  whitelist_headers=summary_elements)
    old_cves = pivot_rows_to_keys(old_cve_header, old_cve_rows, key_name='CVE_ID',
                                  whitelist_headers=summary_elements)
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
    updated = [new_items[x] for x in filter(lambda x: new_items[x] != old_items[x], intersected_ids)]

    return {
        'added': added,
        'removed': removed,
        'updated': updated
    }


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


def pivot_rows_to_keys(header_list, row_list, key_name, whitelist_headers=None):
    """
    Slightly more direct converter for header,row combo into a dict of objects

    :param header_list:
    :param row_list:
    :param key_name:
    :return:
    """
    header_map = {v: header_list.index(v) for v in
                  filter(lambda x: not whitelist_headers or x in whitelist_headers or x == key_name, header_list)}
    key_idx = header_map[key_name]
    return {x[key_idx]: {k: x[v] for k, v in header_map.items()} for x in row_list}


def filter_record_keys(record_list, whitelist_keys):
    """
    Filter the list records to remove verbose entries and make it suitable for notification format
    :param record_dict: dict containing values to process
    :param whitelist_keys: keys to leave in the record dicts
    :return: a new list with dicts that only contain the whitelisted elements
    """

    filtered = map(lambda x: {k: v for k, v in filter(lambda y: y[0] in whitelist_keys, x.items())}, record_list)
    return filtered
