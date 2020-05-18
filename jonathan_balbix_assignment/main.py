import requests
from bs4 import BeautifulSoup
import unicodedata
import copy
import json

def parse_site(url):
    page = requests.get(url)
    soup = BeautifulSoup(page.content, 'html.parser')


    source = 'adobe'
    published_date = None
    timestamp = None
    url = None
    product = None
    vendor = None

    div = soup.find_all("div", class_="text")

    for element in div:
        summary = element.find('p').text.split()
        end = summary.index('has')
        vendor = ' '.join(summary[:end]).lower()
        break


    metas = soup.findAll('meta')
    for meta in metas:
        metaname = meta.get('name', '')
        if metaname == 'publishDate':#published_date
            published_date = meta['content'].lower()
        if metaname == 'lastModifiedDate':#timestamp
            timestamp = meta['content'].lower()
        if metaname == 'publishExternalUrl':#url
            url = meta['content'].lower()
        if metaname == 'description':
            desc = meta['content'].split()
            end = meta['content'].split().index('|')
            product = ' '.join(desc[4:end]).lower()


    tables = soup.findAll('div',class_='table parbase section')

    affectedVersions = tables[1]
    solution = tables[2]
    vulnerabilityDetails = tables[3]

    avrows = affectedVersions.find_all(['tr'])

    avr_mapping = []

    for tr in avrows:
        if avrows.index(tr) == 0 : 
            header = [th.getText().strip().lower() for th in tr.find_all('th') if th.getText().strip() != '']
            avr_mapping = [header]
        else:
            td = tr.find_all('td')
            row = [unicodedata.normalize("NFKD", i.text).strip().lower() for i in td]
            avr_mapping.append(row)

    vdrows = vulnerabilityDetails.find_all(['tr'])
    vdr_mapping = []

    for tr in vdrows:
        td = tr.find_all('td')
        row = [unicodedata.normalize("NFKD", i.text).strip().lower() for i in td]
        vdr_mapping.append(row)

    vdr_header = vdr_mapping[0]
    avr_header = avr_mapping[0]

    def processKeyMetrics(index):
        affected_versions_column = False
        template = {'timestamp': timestamp, 'published_date': published_date, 'id': None, 'url': url, 'name': product, 'description': None,'cpes': {'cpe_list': []}}
        cpe_temp = {'vendor': vendor, 'product': product, 'category': 'a', 'versionStartIncluding': None, 'versionEndIncluding': None}
        for i in range(len(vdr_header)):
            if vdr_header[i] == 'vulnerability category':
                template['description'] = vdr_mapping[index][i]
            if vdr_header[i] == 'cve number' or vdr_header[i] == 'cve numbers':
                template['id'] = vdr_mapping[index][i].upper()
            if vdr_header[i] == 'affected versions':
                affected_versions_column = True
                version_range = [v.split()[-1] for v in vdr_mapping[index][i].split('\n') if v != '']
                if version_range[0] == version_range[-1]:
                    cpe_temp['versionEndIncluding'] = version_range[-1]
                else:
                    cpe_temp['versionStartIncluding'] = version_range[0]
                    cpe_temp['versionEndIncluding'] = version_range[-1]
        if not affected_versions_column:
            for i in range(len(avr_header)):
                if avr_header[i] == 'version':
                    version = avr_mapping[index][i]
                    if 'and earlier versions' in version:
                        version = version.split()[0]
                        cpe_temp['versionEndIncluding'] = version
                    else:
                        version = version.split('\n')
                        if version[-1] == version[0]:
                            cpe_temp['versionEndIncluding'] = version[0]
                        else:
                            cpe_temp['versionStartIncluding'] = version[-1]
                            cpe_temp['versionEndIncluding'] = version[0]
        template['cpes']['cpe_list'].append(cpe_temp)
        cpe_list_items = template['cpes']['cpe_list']
        for i in range(len(cpe_list_items)):
            if(cpe_list_items[i]['versionStartIncluding'] == None):
                del cpe_list_items[i]['versionStartIncluding']
        return template

    cves = []

    for i in range(1,len(vdr_mapping)):
        cves.append(processKeyMetrics(i))

    result = {'source': source, 'type': 'vendor', 'cves': cves}

    with open('output.json', 'w') as fp:
        json.dump(result, fp)
        
URL = 'https://helpx.adobe.com/security/products/experience-manager/apsb20-01.html'
# URL = 'https://helpx.adobe.com/security/products/bridge/apsb20-19.html'
URL= 'https://helpx.adobe.com/security/products/after_effects/apsb20-21.html'
#URL='https://helpx.adobe.com/security/products/magento/apsb20-02.html'
URL= 'https://helpx.adobe.com/security/products/illustrator/apsb20-20.html'
parse_site(URL)

with open('output.json') as json_file:
    data = json.load(json_file)
    print(data['cves'])


