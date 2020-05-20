import sys
import requests
from bs4 import BeautifulSoup
import json
from datetime import datetime
import re


"""
Check if a given string is a version number
"""
def is_version_number(text):
    for num in text.split('.'):
        if not num.isdigit():
            return False
    return True


"""
Get version number from a string
"""
def get_version(text):
    for word in text.split():
        if is_version_number(word):
            return word


"""
Get cpe from a table row. The version is retrieved fro column with index version_col
"""
def get_cpe(row, version_col, vendor, name):
    versions = row.find_all('td')[version_col].find_all('p')
    cpe = {}
    if versions:  # specify start and end version
        version_start_including = get_version(versions[0].text.strip())
        version_end_including = get_version(versions[-1].text.strip())
        cpe['versionStartIncluding'] = version_start_including
        cpe = {
            'vendor': vendor,
            'product': name.lower().replace(' ', '_'),  # change to snake case
            'category': 'a',
            'versionStartIncluding': version_start_including,
            'versionEndIncluding': version_end_including
        }
    else:  # specify only end version
        version_end_including = get_version(row.find_all('td')[version_col].text.strip())
        cpe = {
            'vendor': vendor,
            'product': name.lower().replace(' ', '_'),  # change to snake case
            'category': 'a',
            'versionEndIncluding': version_end_including
        }
    return cpe


def main(url):
    page = requests.get(url)
    soup = BeautifulSoup(page.content, 'html.parser')
    output = {
        'source': 'adobe',
        'type': 'vendor'
    }

    tables = soup.find_all('table')

    # Get published_date
    date_format = '%Y-%m-%dT%H:%MZ'
    published_date = tables[0].find_all('tr')[1].find_all('td')[1].text.strip()
    published_date = datetime.strptime(published_date, '%B %d, %Y')
    published_date = datetime.strftime(published_date, date_format)

    # Get timestamp
    timestamp = datetime.today()
    timestamp = datetime.strftime(timestamp, date_format)

    # Get vendor and name
    page_description = soup.find('div', class_='page-description').text.strip()
    name = ' '.join(page_description.split('|')[0].split()[4:])
    if len(name.split()) > 1:
        name = ' '.join(name.split()[1:])  # remove vendor from product name
    summary_header = soup.find('h2', id='Summary')
    summary = summary_header.parent.parent.next_sibling.next_sibling.text.strip()
    vendor = summary.split()[0].lower()

    # Get cpes from  'Affect versions' table
    affected_version_table = soup.find_all('table')[1]
    all_cpes = []
    for row in affected_version_table.find_all('tr')[1:]:
        cpe = get_cpe(row=row, version_col=1, vendor=vendor, name=name)
        all_cpes.append(cpe)

    # Get column index from Vulnerability Details Table for each attributes
    # Affected Versions, CVE Number, Vulnerability Category
    vulnerability_details_table = tables[3]
    version_col = None
    id_col = None
    desc_col = None
    for i, header, in enumerate(vulnerability_details_table.find('tr').find_all('td')):
        if header.find(string=re.compile('Affected Versions')):
            version_col = i
        if header.find(string=re.compile('CVE Number')):
            id_col = i
        if header.find(string=re.compile('Vulnerability Category')):
            desc_col = i

    # Get cves
    cves = []
    for row in vulnerability_details_table.find_all('tr')[1:]:
        # Get CVE number(s)
        ids = row.find_all('td')[id_col].find_all('p')
        if not ids:  # there is only CVE number in the box
            id = row.find_all('td')[id_col]
            ids = [id]
        ids = [id.text.strip() for id in ids]

        # get description
        description = row.find_all('td')[desc_col].text.strip().lower()

        # Get cpe_list
        cpe_list = []
        if version_col:  # Get cpes from Vulnerability Details Table
            cpe = get_cpe(row=row, version_col=version_col, vendor=vendor, name=name)
            cpe_list.append(cpe)
        else:  # Get apes from Affected Versions Table
            cpe_list = all_cpes

        for id in ids:
            cve = {
                'timestamp': timestamp,
                'published_date': published_date,
                'id': id,
                'url': url,
                'name': name,
                'description': description,
                'cpes': {'cpe_list': cpe_list}
            }
            cves.append(cve)
    output['cves'] = cves

    # Save json to file
    with open('output.json', 'w') as f:
        json.dump(output, f, indent=3)


if __name__ == '__main__':
    if len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        print('Error: must provide 1 command line argument for url')



