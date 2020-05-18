import sys
import requests
import datetime
import json
import re
import copy
from bs4 import BeautifulSoup


def main():
    if (len(sys.argv) > 2):
        print("Invalid arguments.")
    else:
        url = sys.argv[1]
        source = requests.get(url).text
        soup = BeautifulSoup(source, 'lxml')
        keys = {
            "source": "adobe",
            "type": "vendor",
            "cves": [
            ]
        }
        parse_H(soup, keys)

# parse html
def parse_H(soup, keys):
    url = sys.argv[1]
    cves_dict = {
        "timestamp": "",
        "published_date": "",
        "id": "",
        "url": url,
        "name": "",
        "description": "",
        "cpes": {
            "cpe_list": [

            ]
        }
    }

    cpes_dict = {
        "vendor": "",
        "product": "",
        "category": "a",
    }

    # put html text into list of lists
    data = []
    tbody = soup.find_all('tr')
    for row in tbody:
        cols = row.find_all('td')
        cols = [ele.text.strip() for ele in cols]
        data.append([ele for ele in cols if ele])
    data = [d for d in data if d != []]
    for d in data:
        print(d)
        print("\n")

    # parse id
    id_table_index = 0
    id_index = 0
    ids = []
    for i in range(len(data)):
        for j in range(len(data[i])):
            if('CVE Number' in data[i][j]):
                id_table_index = i
                id_index = j
                print(data[i])
                print(data[i][j])
                break
    ids = [data[k][id_index] for k in range(id_table_index+1, len(data))]
    print(ids)
    print(id_table_index)
    print(id_index)

    # parse name
    name_table_index = 0
    name_index = 0
    name_end = 0
    name = ""
    temp = []
    names = []
    for i in range(len(data)):
        for j in range(len(data[i])):
            if('Product' in data[i][j]):
                name_table_index = i+1
                for k in range(i + 1, len(data)):
                        if "Vulnerability Category" in data[k][j]:
                            name_end = k
                            break
                name_index = j
                name = data[i+1][j]
                print(i)
                print(j)
                break
    temp = [data[k][name_index] for k in range(name_table_index, name_end)]
    
    for n in temp:
        if("." not in n):
            names.append(n)
            
    print("NAMES: ",names)

    # parse description
    desc_table_index = 0
    desc_index = 0
    desc = []
    for i in range(len(data)):
        for j in range(len(data[i])):
            if('Vulnerability Category' in data[i][j]):
                desc_table_index = i
                desc_index = j
                desc = [data[k][j] for k in range(i+1, len(data))]
                break
    print("DESC: ",desc)

    # parse vendor and product
    vendor = (name.split(" ")[0]).lower()
    product = ('_'.join(name.split(" ")[1:])).lower()
    print(vendor)
    print(product)

    # check between 2 websites
    has_av = False
    for row in data:
        if "Affected Versions" in row:
            has_av = True
            break

    ver = []
    if has_av:
        # affectedversion
        ver_table_index = 0
        ver_index = 0
        ver_end = 0
        for i in range(len(data)):
            for j in range(len(data[i])):
                if('Affected Versions' in data[i][j]):
                    ver_table_index = i
                    for k in range(i + 1, len(data)):
                        if "Vulnerability Impact" in data[k][j]:
                            ver_end = k
                            break
                    ver_index = j
                    break
        ver_end = len(data) if ver_end == 0 else ver_end #last table
        print(ver_end)
        ver = [data[k][ver_index] for k in range(ver_table_index+1, ver_end)]
        ver = [v.split('\n') for v in ver]
        ver = [[v_.split(' ')[len(v_.split(' ')) - 1]
                for v_ in v if v_ != ''] for v in ver]
        
    else:
        # version
        ver_table_index2 = 0
        ver_index2 = 0
        ver_end2 = 0
        for i in range(len(data)):
            for j in range(len(data[i])):
                if('Version' in data[i][j]):
                    ver_table_index2 = i
                    for k in range(i + 1, len(data)):
                        if "Vulnerability Impact" in data[k][j]:
                            ver_end2 = k
                            break
                    ver_index2 = j
                    break
        ver_end2 = len(data) if ver_end2 == 0 else ver_end2
        print(ver_end2)
        ver = [data[k][ver_index2]
               for k in range(ver_table_index2+1, ver_end2)]
        ver = [v.split('\n') for v in ver]
        ver = [[v_.split(' ')[len(v_.split(' ')) - 1]
                for v_ in v if v_ != ''] for v in ver]

        print("VER: ", ver)

    # format to keys
    for i in range(len(ids)):
        print(i)
        cves_copy = copy.deepcopy(cves_dict)
        cpes_copy = copy.deepcopy(cpes_dict)
        now = datetime.datetime.now()
        cves_copy['timestamp'] = now.strftime("%Y-%m-%dT%H:%MZ")
        cves_copy['published_date'] = data[1][1] # data is always at 2nd row 2nd col
        cves_copy['id'] = ids[i]
        if(len(names)==1):
            cves_copy['name'] = names[0]
        else:
            cves_copy['name'] = names[i]
        cves_copy['description'] = desc[i]
        cpes_copy['vendor'] = vendor
        cpes_copy['product'] = product
        if(len(ver[i]) > 1):
            cpes_copy['versionStartIncluding'] = ver[i][0]
        cpes_copy['versionEndIncluding'] = ver[i][len(ver[i])-1]
        cves_copy['cpes']['cpe_list'].append(cpes_copy)
        keys['cves'].append(cves_copy)

        print(cves_copy)

    # create json file
    with open('data.json', 'w') as f:
        json.dump(keys, f, indent=4)


if __name__ == "__main__":
    main()