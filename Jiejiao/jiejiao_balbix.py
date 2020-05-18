
from bs4 import BeautifulSoup as BS

from selenium import webdriver
import chromedriver_autoinstaller
import pandas as pd
from datetime import datetime
from collections import OrderedDict
import calendar, requests
import json, re, argparse
# install lxml, requests, pandas

driver = None

headers = {
    'cookie': "",
    'Host': 'helpx.adobe.com',
    'Referer': 'https://helpx.adobe.com/',
    'user-agent': "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) Ap"
    "pleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safar"
    "i/604.1",
    'Accept-Encoding': 'gzip'}

def get_timestamp():
    timestamp_format = "%Y-%m-%dT%H:%MZ"
    now = datetime.now()
    timestamp = now.strftime(timestamp_format)
    return timestamp

def parse_date(date_string): #formatted as Month and day
    m, d, y = date_string.split(' ')
    d = d.split(',')[0]
    abbr_to_num = {name: num for num, name in enumerate(calendar.month_abbr) if num}
    m_num = abbr_to_num[m.capitalize()[:3]]
    timestamp_format = "{}-{}-{}T00:00Z"
    return timestamp_format.format(y, str(m_num).zfill(2), d)

def special_match(strg):
    search = re.compile(r'^[0-9\.]*$').search
    return bool(search(strg))

def get_cpe_dict(ver_string, vendor_name, prod_name):
    newCPE = OrderedDict([('vendor', vendor_name), ('product', prod_name),
                          ('category', 'a')])

    ver_string = ver_string.replace('\u202f', ' ')
    ver_string = ver_string.replace(u'\xa0', u' ')

    nums = [strg for strg in ver_string.split(' ') if special_match(strg)]

    nums.sort()
    if len(nums) == 1:
        newCPE.update({'versionEndIncluding': nums[0]})
    else:
        newCPE.update({'versionStartIncluding': nums[0]})
        newCPE.update({'versionEndIncluding': nums[-1]})
    return newCPE

def get_cpe_for_all(aff_ver_tbl, vendor_name, prod_name):
    cpe_list = []
    version_key = None
    for col in aff_ver_tbl.columns:
        if 'version' in col.lower():
            version_key = col
        elif 'update number' in col.lower():
            version_key = col
    if version_key is None:
        print('------- Unable to parse key for version number in table -------')
        exit()
    for idx, row in aff_ver_tbl.iterrows():
        if pd.isna(row[version_key]):
            continue
        elif row[version_key] == version_key:
            continue
        cpe_list += [get_cpe_dict(str(row[version_key]), vendor_name, prod_name)]
    return cpe_list

def URLisValid(url):
    # validating URL since it's hard to do with selenium #
    page = requests.get(url, headers=headers)
    if page.status_code == 200:
        print('----------------------- URL is validated --------------------------')
    else:
        print('---------------- Invalid URL, exiting program ---------------------')
        exit()

if __name__ == '__main__':
    #url='https://helpx.adobe.com/security/products/experience-manager/apsb20-01.html'
    parser = argparse.ArgumentParser(description="Parses command.")
    parser.add_argument("-u", "--url", type=str, help="Url to parse.")
    parser.add_argument("-o", "--output_file", type=str, default="result.json",
                        help="Name of json file to save data")
    options = parser.parse_args()

    #url='https://helpx.adobe.com/security/products/magento/apsb20-02.html'
    url = options.url
    prod_name = url.split('products/')[1].split('/')[0].replace('-', '_')
    #vendor_name = prod_name.split(' ')[0].lower()

    URLisValid(url)

    # get timestamp
    timestamp = get_timestamp()

    # start selenium's chrome driver and get loaded page
    chromedriver_autoinstaller.install()
    driver = webdriver.Chrome()
    driver.get(url)

    html = driver.page_source
    bs = BS(html, 'html.parser')

    # get published_date and page description
    published_date = bs.find('span', {'class': 'publish-date'})

    descp = bs.find('div', {'class':'page-description'})

    if published_date is None or descp is None:
        print('---- No published_date or page description found in page, exiting ---')
        driver.close()
        exit()

    published_date = parse_date(published_date.text)
    name = descp.text.split('for')[1].split('|')[0].strip(' ')
    vendor_name = name.split(' ')[0].lower()

    potential_labels = ['Affectedproductversions', 'AffectedVersions',
                        'Affectedversions', 'affectedversions']
    for label in potential_labels:
        affprodTag = bs.find('h2', id=label)
        if affprodTag is not None:
            break

    if affprodTag is None:
        print('------ No affected versions table found in page, exiting ------')
        driver.close()
        exit()

    affVerTbl = affprodTag.find_next()
    while(affVerTbl.attrs['class'][0] != 'table'):
        affVerTbl = affVerTbl.find_next()

    aff_ver_tbl = pd.read_html(str(affVerTbl))[0]
    if aff_ver_tbl.columns.dtype == 'int64':
        aff_ver_tbl.columns = aff_ver_tbl.iloc[0] #convert 1st row to be col names

    cpe_for_all = get_cpe_for_all(aff_ver_tbl, vendor_name, prod_name)

    tble_labels_tups = [('h2', 'Vulnerabilitydetails'), ('h2', 'VulnerabilityDetails'),
                        ('h3', 'Vulnerabilitydetails'), ('h3', 'VulnerabilityDetails')]

    for attr, id in tble_labels_tups:
        tble_name = bs.find(attr, id=id)
        if tble_name is not None:
            break

    if tble_name is None:
        print('------ No VulnerabilityDetails table found in page, exiting ------')
        driver.close()
        exit()

    vulDetTbl = tble_name.find_next()

    while(vulDetTbl.attrs['class'][0] != 'table'):
        vulDetTbl = vulDetTbl.find_next()

    vul_det_list = pd.read_html(str(vulDetTbl))[0]

    if vul_det_list.columns.dtype == 'int64':
        vul_det_list.columns = vul_det_list.iloc[0] #convert 1st row to be col names

    Num_key, Aff_key, Descrp_key = None, None, None
    for key in list(vul_det_list.columns):
        if 'CVE' in key:
            Num_key = key
        elif 'affected' in key.lower():
            Aff_key = key
        elif 'vulnerability' in key.lower() and 'category' in key.lower():
            Descrp_key = key

    if Num_key is None:
        print("----- No Identifier found for CVE -----")
        driver.close()
        exit()
    elif Descrp_key is None:
        print("----- No description found for CVE -----")
        driver.close()
        exit()

    CVEs = []
    for i, row in vul_det_list.iterrows():
        if pd.isna(row[Num_key]):
            continue
        for cve_num in row[Num_key].split(' '):
            if len(cve_num.strip(' ')) == 0:
                continue
            newCVE = OrderedDict([
                      ('timestamp', timestamp), ('published_date', published_date),
                      ('id', cve_num), ('url', url), ('name', name),
                      ('description', row[Descrp_key].lower())])
            if row[Descrp_key] == Descrp_key:
                continue
            if Aff_key is None:
                aff_vers_list = cpe_for_all
            else:
                aff_vers_list = [get_cpe_dict(str(row[Aff_key]), vendor_name, prod_name)]
            newCVE.update({'cpes': aff_vers_list})
            CVEs += [newCVE]

    final_dict = OrderedDict([('source', 'adobe'), ('type', 'vendor'), ('cves', CVEs)])
    #final_str = json.dumps(final_dict)
    with open(options.output_file, 'w') as f:
        json.dump(final_dict, f)
    driver.close()
