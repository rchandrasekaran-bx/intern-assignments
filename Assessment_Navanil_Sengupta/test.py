import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import datetime
import tldextract
import re
import sys

def DateParse(dateDetails):
    months=["january","february","march","april","may","june","july","august","september","october","november","december"]
    mon = str(months.index(dateDetails[0])+1).zfill(2)
    year = dateDetails[2]
    date = dateDetails[1]
    return (year+"-"+mon+"-"+date+"T00:00Z")

def scan(url):
    soup = bs(requests.get(url).content, "html.parser")
    # print(soup)
    # tb = soup.find_all('table')
    # look for all the tables in the page. It will change with different vendors from the page. Considered the adobe samples here.
    tb = soup.find_all("div", {"class": "table parbase section"})

    cpe_list=[]
    bulletinDetails=[]
    vulList=[]
    vendor_output = ""
    product_output = ""

    for table_no, table in enumerate(tb):
        # print(table_no)
        rows = table.find_all('tr')
        for row in rows:
            cols = row.find_all('td')
            cols = [x.text.strip() for x in cols]
            if table_no == 0:
                """
                Parsing Bulletin Details.
                """
                bulletinDetails.append(cols)

            elif table_no == 1:
                """
                Parsing Affected Versions.
                """
                try:
                    # print(cols)
                    vendor= cols[0].lower().split(" ")[0]
                    product = cols[0].lower().replace(vendor,"").strip()
                    vendor_output = vendor
                    product_output = product
                    endVersion = cols[1].lower().split(" ")[0]
                    cpe_dict={
                        "vendor": vendor,
                        "product": product,
                        "category": "a",
                        "versionEndIncluding": endVersion
                    }
                    cpe_list.append(cpe_dict)
                except:
                    continue
            elif table_no == 3:
                """
                Parsing Vulnerablity Details.
                """
                vulList.append(cols)
                # print(cols)
    dateDetails = bulletinDetails[1][1].lower().replace(",","").split()
    publishedDate = DateParse(dateDetails)

    # print(cpe_list)
    # print(publishedDate)
    # print(vulList)
    cve_list = []

    CVE_index = [(vulList[0].index(x)) for x in vulList[0] if "CVE" in x]
    Vul_Cat = [(vulList[0].index(x)) for x in vulList[0] if "Vulnerability Category" in x]

    for vul in vulList[1:]:
        now = datetime.datetime.now()
        timestamp = now.strftime('%Y-%m-%dT%H:%MZ')

        description = vul[Vul_Cat[0]]

        id = vul[CVE_index[0]]
        name = product_output         
        cve = {
            "timestamp": str(timestamp),
            "published_date": str(publishedDate),
            "id" : str(id),
            "url" : str(url),
            "name" : name,
            "description": str(description),
            "cpes": {
                "cpe_list" : cpe_list
            }

        }
        cve_list.append(cve)

    # print(cve_list)
    ext = tldextract.extract(url)
    source = ext.domain            
    typ = "vendor"
    jsonOutput = {
        "source" : source,
        "type" : typ,
        "cves" : cve_list
    }

    f = open('out.json', 'w')
    f.write(str(jsonOutput))
    f.close()

    return jsonOutput

if __name__ == "__main__":

    inp_url = sys.argv[1]

    url = inp_url
    print(scan(url))