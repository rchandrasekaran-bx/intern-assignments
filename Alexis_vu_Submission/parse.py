""" PARSING FUNCTIONS """

# Import Libraries
from datetime import datetime           # date & time library
import requests                         # HTTP library
from bs4 import BeautifulSoup           # web scraping library
import pandas as pd                     # data analysis library

# Import Files
import constant                         # constant definitions
import helper                           # misc. helper functions


""" 
    Main URL parsing function.
"""


def parse(url: str) -> dict:
    # open web page
    page = requests.get(url)

    # create HTML tree with BeautifulSoup
    content = BeautifulSoup(page.text, 'html.parser')

    # get dict of page's headers and their indices
    headers = get_headers(content)

    # get dict of page's tables and their indices
    tables = get_tables(content)

    # create container for data
    data = {'source': constant.SOURCE,
            'type': constant.TYPE}

    # map table indices
    summary_idx = -1
    affected_idx = -1
    vulnerability_idx = -1

    # loop through header names
    # if keyword in name -> val will be its table index
    for name in headers.keys():
        if 'summary' in name:
            summary_idx = headers[name]
        elif 'affected' in name:
            affected_idx = headers[name]
        elif 'vulnerability' in name:
            vulnerability_idx = headers[name]

    # reference all tables using indices found
    summary_table = tables[summary_idx]
    affected_table = tables[affected_idx]
    vulnerability_table = tables[vulnerability_idx]

    # -- BEGIN DATA PARSING

    # parse summary table
    # retrieves: published_date
    published_date = parse_summary(summary_table)

    # parse page description
    # retrieves: vendor and product name
    product = parse_description(content.find(class_='page-description'))

    # parse affected versions table
    # (only if affected versions doesn't exist in vulnerability details table)
    # retrieves: CPE list
    cpes = None
    if 'Affected Versions' not in vulnerability_table['data'][0]:
        cpes = parse_affected(affected_table, product)

    # parse vulnerability
    # retrieves: CVE list using previously parsed information
    data['cves'] = parse_vulnerability(vulnerability_table, published_date, url, product, cpes)

    return data


"""
    Processes headers from security bulletin's HTML content.
"""


def get_headers(content: BeautifulSoup) -> dict:
    # retrieve all divs with header class name
    header_list = content.find_all(class_='header header-top')
    # track table index for later mapping
    table_index = 0
    headers = {}

    # find and append headers
    for header in header_list:
        header_div = header.find('h2')
        header_name = header_div.text.strip().lower()
        headers[header_name] = table_index
        table_index += 1

    return headers


"""
    Processes tables from security bulletin's HTML content.
"""


def get_tables(content: BeautifulSoup) -> dict:
    # retrieve all table divs
    table_list = content.find_all('table')
    # track table index for later mapping
    table_index = 0
    tables = {}

    # find table data frames, stringify and store in dict
    # 'split' option organizes tables into dict with keys: index, column, and data
    for table in table_list:
        data_frame = pd.read_html(str(table))
        tables[table_index] = data_frame[0].to_dict(orient='split')
        table_index += 1

    return tables


"""
    Parses summary table containing published data.
"""


def parse_summary(table: any) -> str:
    date = ''

    # find date column index
    for col in table['columns']:
        title = table['data'][0][col]

        # if date column found, get data at same col index
        if 'date' in title.lower():
            date = table['data'][1][col]

    # format date
    date = date.replace(',', '')
    datetime_obj = datetime.strptime(date, '%B %d %Y')
    formatted_date = datetime_obj.strftime('%Y-%m-%dT%H:%MZ')

    return formatted_date


"""
    Parses security bulletin's description containing product information.
"""


def parse_description(data: any) -> dict:
    # get text from data, strip any whitespace
    text = data.text.strip()

    # find product string start and end to find substring
    start = text.find('for') + 3
    end = text.find('|', start)
    substring = text[start:end].strip()

    # split product name by space
    product = substring.split(' ')

    # create product info container
    result = {}

    product_vendor = product[0].lower()
    result['vendor'] = product_vendor

    # if product only contains one string, same as vendor name
    # otherwise, product name = remaining strings
    product_name = str('_').join(product[1:]).lower() if len(product) > 1 else product_vendor
    result['product'] = product_name

    return result


"""
    Parses Affected Versions table containing CPE information.
"""


def parse_affected(table: any, product: dict):
    # create container mirroring JSON structure
    cpes = {'cpe_list': []}

    # process each table data row
    for row in table['data']:
        # create new CPE structure
        # False flag to indicate no version range
        cpe = helper.create_cpe(product, False)

        # check each column until Version column found
        for i in range(0, len(table['columns'])):
            table_head = table['columns'][i].lower()
            # get version no. end, then append to CPE list
            if 'version' == table_head:
                version = row[i]
                version = version.split(' ')
                version_no = version[0]
                cpe['versionEndIncluding'] = version_no

        cpes['cpe_list'].append(cpe)

    return cpes


"""
    Parses Vulnerability Details table containing CVE information.
    Creates rest of data dict structure using already parsed information.
"""


def parse_vulnerability(table: any, published_date: str, url: str, product: dict, cpes: any) -> list:
    cves = []
    table_head = table['data'][0]
    table_data = table['data'][1:]

    # if CPE list none, need to create own CPEs from affected versions col
    if cpes is None:
        # process each row of table data
        for row in table_data:
            # create CVE and CPE structures
            # True flag for potentially having range
            cve = helper.create_cve(published_date, url, product)
            cpe = helper.create_cpe(product, True)

            # for each col, check title and store accordingly
            for col in table['columns']:
                column_title = table_head[col].lower()
                if 'category' in column_title:
                    description = row[col]
                    cve['description'] = description.lower()
                elif 'cve' in column_title:
                    cve_number = row[col]
                    cve['id'] = cve_number
                elif 'affected' in column_title:
                    versions = row[col].split(' ')
                    start = helper.find_start(versions)
                    end = helper.find_end(versions)
                    cpe['versionEndIncluding'] = str(end)

                    # if version no. start == end, no range
                    # remove field from CPE dict
                    if start == end:
                        cpe.pop('versionStartIncluding')
                    else:
                        cpe['versionStartIncluding'] = str(start)

            # mirror JSON structure and append CVE and CPE
            cve['cpes']['cpe_list'] = []
            cve['cpes']['cpe_list'].append(cpe)
            cves.append(cve)
    else:
        # if CPE list not none, just need to process CVE info

        # process each row of table data
        for row in table_data:
            # create CVE structure
            cve = helper.create_cve(published_date, url, product)

            # for each column, check title and store accordingly
            for col in table['columns']:
                column_title = table_head[col].lower()
                if 'category' in column_title:
                    description = row[col]
                    cve['description'] = description.lower()
                elif 'cve' in column_title:
                    cve_number = row[col]
                    cve['id'] = cve_number

            # CPE list remains same, just add to cpes field and add CVE
            cve['cpes'] = cpes
            cves.append(cve)

    return cves
