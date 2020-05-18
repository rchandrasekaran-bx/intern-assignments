import datetime
import json
import re
import scrapy
import sys

if len(sys.argv) == 2:
    url = sys.argv[1]
elif len(sys.argv) == 1:
    sys.exit('no url was provided')
else:
    sys.exit('too many arguments provided')

type = "vendor"
category = "a"

# get the product name from the url
sections = url.split('/')
for i in range(len(sections)):
    if sections[i] == "products":
        productName = sections[i+1]

class AdobeSpider(scrapy.Spider):
    name = 'adobe'
    start_urls = [url]

    def parse(self, response):
        last_modified_date = response.xpath("//meta[@name='lastModifiedDate']/@content").extract()[0]
        print("last_modified_date: ", last_modified_date)

        if response.xpath("//table/tbody//tr/td[contains(., 'Date Published')]"):
            published_date = response.xpath("//table/tbody//tr/td[contains(., 'Date Published')]/../../tr[2]/td[2]//text()").extract()
        elif response.xpath("//table/tbody//tr/th[contains(., 'Date Published')]"):
            published_date = response.xpath("//table/tbody//tr/th[contains(., 'Date Published')]/../../tr[2]/td[2]//text()").extract()
        published_date = clean(published_date)
        print("published_date: ", published_date)
        published_date = datetime.datetime.strptime(published_date[0], "%B %d, %Y")

        if response.xpath("//table/tbody//tr/th[contains(., 'Product')]"):
            products = response.xpath("//table/tbody//tr/th[contains(., 'Product')]/../..//tr/td[1]/text()").extract()
        products = clean(products)
        print("products: ", products)
        if any("adobe" in s for s in products) or any("Adobe" in s for s in products):
            vendor = "adobe"
        else:
            vendor = productName

        multiple_versions = []
        if response.xpath("//table/tbody//tr/td[.='Affected Versions']"):
            versionRow = int(float(response.xpath("count(//table/tbody//tr/td[.='Affected Versions']/preceding-sibling::td)").extract()[0])) + 1
            vulnerabilityRows = int(float(response.xpath("count(//table/tbody//tr/td[.='Affected Versions']/../../tr)").extract()[0]))
            print("versionRow: ", versionRow)
            print("vulnerabilityRows: ", vulnerabilityRows)
            for row in range(2, vulnerabilityRows + 1):
                tempVersions = response.xpath("//table/tbody//tr/td[contains(translate(., 'CVE N', 'CVE n'), 'CVE number')]/../../tr[" + str(row) + "]/td[" + str(versionRow) + "]//text()").extract()
                tempVersions = clean(tempVersions)
                for i in range(len(tempVersions)):
                    # find version number(s) in version string
                    tempVersions[i] = re.findall('[\d.]+', tempVersions[i])[0]
                tempVersions = [float(i) for i in tempVersions]

                if len(tempVersions) > 1:
                    multiple_versions.append([min(tempVersions), max(tempVersions)])
                else:
                    multiple_versions.append([max(tempVersions)])
            print("multiple_versions: ", multiple_versions)
        elif response.xpath("//table/tbody//tr/th[.='Version']"):
            versionRow = int(float(response.xpath("count(//table/tbody//tr/th[.='Version']/preceding-sibling::th)").extract()[0])) + 1
            print("versionRow: ", versionRow)
            versions = response.xpath("//table/tbody//tr/th[.='Version']/../..//tr/td[" + str(versionRow) + "]//text()").extract()
        elif response.xpath("//table/tbody//tr/th[.='Affected Versions']"):
            versionRow = int(float(response.xpath("count(//table/tbody//tr/th[.='Affected Versions']/preceding-sibling::th)").extract()[0])) + 1
            print("versionRow: ", versionRow)
            versions = response.xpath("//table/tbody//tr/th[.='Affected Versions']/../..//tr/td[" + str(versionRow) + "]//text()").extract()
        elif response.xpath("//table/tbody//tr/th[.='Affected version']"):
            versionRow = int(float(response.xpath("count(//table/tbody//tr/th[.='Affected version']/preceding-sibling::th)").extract()[0])) + 1
            print("versionRow: ", versionRow)
            versions = response.xpath("//table/tbody//tr/th[.='Affected version']/../..//tr/td[" + str(versionRow) + "]//text()").extract()
        elif response.xpath("//table/tbody//tr/td[.='Update number']"):
            print("4")
            versionRow = int(float(response.xpath("count(//table/tbody//tr/td[.='Update number']/preceding-sibling::td)").extract()[0])) + 1
            print("versionRow: ", versionRow)
            versions = response.xpath("//table/tbody//tr/td[.='Update number']/../..//tr/td[" + str(versionRow) + "]//text()").extract()

        multiple_cpe_list = []
        if len(multiple_versions) > 0:
            for version in multiple_versions:
                if len(version) > 1:
                    multiple_cpe_list.append([{
                        "vendor": vendor,
                        "product": productName,
                        "category": category,
                        "versionStartIncluding": version[0],
                        "versionEndIncluding": version[1]
                    }])
                else:
                    multiple_cpe_list.append([{
                        "vendor": vendor,
                        "product": productName,
                        "category": category,
                        "versionEndIncluding": version[0]
                    }])
        else:
            versions = clean(versions)
            tempVersions = versions
            versions = []
            for i in range(len(tempVersions)):
                # find version number(s) in version string
                version = re.findall('[\d.]+', tempVersions[i])
                if len(version) != 0:
                    versions.insert(i, version[0])
            print("versions: ", versions)

            cpe_list = []
            for version, product in zip(versions, products):
                cpe_list.append({
                    "vendor": vendor,
                    "product": productName,
                    "category": category,
                    "versionEndIncluding": version
                })

        ids = []
        descriptions = []
        if response.xpath("//table/tbody//tr/td[contains(translate(., 'CVE N', 'CVE n'), 'CVE number')]"):
            vulnerabilityRows = int(float(response.xpath("count(//table/tbody//tr/td[contains(translate(., 'CVE N', 'CVE n'), 'CVE number')]/../../tr)").extract()[0]))
            idRow = int(float(response.xpath("count(//table/tbody//tr/td[contains(translate(., 'CVE N', 'CVE n'), 'CVE number')]/preceding-sibling::td)").extract()[0])) + 1
            descriptionRow = int(float(response.xpath("count(//table/tbody//tr/td[contains(., 'Vulnerability Category')]/preceding-sibling::td)").extract()[0])) + 1
            print("vulnerabilityRows: ", vulnerabilityRows)
            print("idRow: ", idRow)
            print("descriptionRow: ", descriptionRow)
            for row in range(2, vulnerabilityRows+1):
                tempIds = response.xpath("//table/tbody//tr/td[contains(translate(., 'CVE N', 'CVE n'), 'CVE number')]/../../tr[" + str(row) + "]/td[" + str(idRow) + "]//text()").extract()
                tempDescription = response.xpath("//table/tbody//tr/td[contains(translate(., 'CVE N', 'CVE n'), 'CVE number')]/../../tr[" + str(row) + "]/td[" + str(descriptionRow) + "]//text()").extract()
                tempDescription = clean(tempDescription)
                tempIds = clean(tempIds)
                for id in tempIds:
                    ids.append(id)
                    descriptions.append(tempDescription[0])
        elif response.xpath("//table/tbody//tr/th[contains(., 'CVE Number')]"):
            vulnerabilityRows = int(float(response.xpath("count(//table/tbody//tr/th[contains(., 'CVE Number')]/../../tr)").extract()[0]))
            idRow = int(float(response.xpath("count(//table/tbody//tr/th[contains(., 'CVE Number')]/preceding-sibling::th)").extract()[0])) + 1
            descriptionRow = int(float(response.xpath("count(//table/tbody//tr/th[contains(., 'Vulnerability Category')]/preceding-sibling::th)").extract()[0])) + 1
            print("vulnerabilityRows: ", vulnerabilityRows)
            print("idRow: ", idRow)
            print("descriptionRow: ", descriptionRow)
            for row in range(2, vulnerabilityRows + 1):
                tempIds = response.xpath("//table/tbody//tr/th[contains(., 'CVE Number')]/../../tr[" + str(row) + "]/td[" + str(idRow) + "]//text()").extract()
                tempDescription = response.xpath("//table/tbody//tr/th[contains(., 'CVE Number')]/../../tr[" + str(row) + "]/td[" + str(descriptionRow) + "]//text()").extract()
                tempDescription = clean(tempDescription)
                tempIds = clean(tempIds)
                for id in tempIds:
                    ids.append(id)
                    descriptions.append(tempDescription[0])
        print("ids: ", ids)
        print("descriptions: ", descriptions)

        cves = []
        if len(multiple_cpe_list) > 0:
            for id, description, list in zip(ids, descriptions, multiple_cpe_list):
                cves.append({
                    "timestamp": last_modified_date,
                    "published_date": published_date.isoformat() + "Z",
                    "id": id,
                    "url": url,
                    "name": productName,
                    "description": description,
                    "cpes": {
                        "cpe_list": list
                    }
                })
        else:
            for id, description in zip(ids, descriptions):
                cves.append({
                    "timestamp": last_modified_date,
                    "published_date": published_date.isoformat() + "Z",
                    "id": id,
                    "url": url,
                    "name": productName,
                    "description": description,
                    "cpes": {
                        "cpe_list": cpe_list
                    }
                })

        jsonData = {
            "source": "adobe",
            "type": type,
            "cves": cves
        }
        # write to json file
        with open('data.json', 'w') as f:
            json.dump(jsonData, f)

# function that cleans an array from response.xpath()
def clean(array):
    # remove '/n' entries from array
    for element in array:
        if element == '\n' or element == '\r\n' or element == '':
            array.remove(element)
    for i in range(len(array)):
        # remove unwanted '\xa0'
        array[i] = array[i].replace(u'\xa0', ' ')
        array[i] = array[i].replace(u'\u202f', ' ')
        array[i] = re.sub(re.compile('<.*?>'), '', array[i])
        # remove white spaces from start and end of array element
        array[i] = array[i].strip()
    array = list(filter(None, array))
    return array
