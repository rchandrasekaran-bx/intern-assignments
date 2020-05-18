""" HELPER FUNCTIONS """

# Import Libraries
from datetime import datetime           # date & time library
import json                             # JSON library

# Import Files
import constant                         # constant definitions

"""
    Creates CPE structure for data dictionary.
"""


def create_cpe(product: dict, has_range: bool) -> dict:
    cpe = {}

    if has_range:
        cpe['vendor'] = product['vendor']
        cpe['product'] = product['product']
        cpe['category'] = constant.CATEGORY
        cpe['versionStartIncluding'] = ''
        cpe['versionEndIncluding'] = ''
    else:
        cpe['vendor'] = product['vendor']
        cpe['product'] = product['product']
        cpe['category'] = constant.CATEGORY
        cpe['versionEndIncluding'] = ''

    return cpe


"""
    Create CVE structure for data dictionary.
"""


def create_cve(published_date: str, url: str, product: dict) -> dict:
    cve = {'timestamp': get_current_time(),
           'published_date': published_date,
           'id': '',
           'url': url,
           'name': product['product'].replace('_', ' ').title(),
           'description': '',
           'cpes': {}}

    return cve


"""
    Creates and formats current datetime object.
"""


def get_current_time() -> str:
    # get current time and format
    now = datetime.now()
    timestamp = now.strftime('%Y-%m-%dT%H:%MZ')

    return timestamp


"""
    Determines start of version no. given range of versions.
"""


def find_start(versions: any) -> float:
    parsed_versions = []

    for version in versions:
        try:
            # check if string is number before appending
            number = float(version)
            parsed_versions.append(number)
        except:
            # if not a number, continue in loop
            continue

    return min(parsed_versions)


"""
    Determines end of version no. given range of versions.
"""


def find_end(versions: any) -> float:
    parsed_versions = []

    for version in versions:
        try:
            # check if string is number before appending
            number = float(version)
            parsed_versions.append(number)
        except:
            # else, continue in loop
            continue

    return max(parsed_versions)


"""
    Creates JSON object from parsed data and outputs to file.
"""


def make_json(data: any) -> None:
    # open file 'output.json'
    with open('output.json', 'w') as out:
        # dump data in file with indent space 2
        json.dump(data, out, indent=2)
