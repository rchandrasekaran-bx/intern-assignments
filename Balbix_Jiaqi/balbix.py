import os
from bs4 import BeautifulSoup
import json
from datetime import datetime
import calendar


# run wget on url from command line
def getURL(url):
    os.system('wget -O website.txt '+url)

# get html of website
def bs4():
    openFile = open("website.txt", 'r').read()
    soup = BeautifulSoup(openFile, "html.parser")
    soup = soup.prettify()
    with open("bs4.html", "w") as file:
        file.write(str(soup))

# get source and name
def getURLInfo(url):
    sources = url.split('.')
    source = sources[0]
    names = ""
    for i in range(len(sources)):
        if "com/" in sources[i]:
            names = sources[i]
            source = sources[i-1]

    names = names.split('/')
    name = ""
    for i in range(len(names)):
        if names[i] == "products":
            name = names[i+1]
    names = name.split("-")
    name = ""
    for part in names:
        name = name+part+" "
    name = name[:-1]

    return (source, name)

# get published date
def getPubDate():
    pubDate = ""
    dateData = open("bs4.html").read().split("Date Published")
    dateData = dateData[1].split('<div class="header parbase section">')
    dateData = dateData[0]
    dateData = dateData.split('\n')
    for lineNum in range(len(dateData)):
        if "<tr>" in dateData[lineNum]:
            tmpline = dateData[lineNum+5].split("  ")
            inc = 1
            while "<" in tmpline[-1]:
                tmpline = dateData[lineNum+5+inc].split("  ")
            pubDate = tmpline[-1]
    pubDate = pubDate.split()
    datetime_object = datetime.strptime(pubDate[0], "%B")
    month_number = datetime_object.month
    month_number = str(month_number)
    if len(month_number) == 1:
        month_number = "0"+str(month_number)
    day = pubDate[1][:-1]
    pubDate = pubDate[2]+"-"+month_number+"-"+day+"T00:00Z"

    return pubDate




# populate list with html data
def parseHTML(data, table, searchStr, indOffset, removeFirst):
    j=0
    for lineNum in range(len(table)):
        if searchStr in table[lineNum]:
            tmpline = table[lineNum+indOffset].split("  ")
            inc = 1
            while "<" in tmpline[-1]:
                tmpline = table[lineNum+indOffset+inc].split("  ")
                inc += 1
            data[j] = tmpline[-1]
            j += 1
    if removeFirst:
        data = data[1:]
    
    return data


def makeJSON(url):
    # get website data
    getURL(url)
    bs4()

    # get source and name
    (source, name) = getURLInfo(url)

    # get published date
    pubDate = getPubDate()

    # GET CVE DICT DATA
    cveList = []
    numCVE = 0
    cves = open("bs4.html").read().split('<h2 id="Vulnerability')
    cveTable = cves[1].split('<div class="header parbase section">')
    cveTable = cveTable[0]
    cveTable = cveTable.split('\n')

    # count number of CVEs
    for line in cveTable:
        if "</tr>" in line:
            numCVE += 1

    # get cves
    CVEID = ["" for i in range(numCVE-1)]
    j=0
    for line in cveTable:
        # assumes one CVE per table entry
        if "CVE-" in line and j < numCVE-1:
            tmpline = line.split("CVE-")
            CVEID[j] = "CVE-"+tmpline[1]
            j += 1

    # get vulnerability categories
    vulCats = ["" for i in range(numCVE)]
    vulCats = parseHTML(vulCats, cveTable, "<tr>", 2, True)

    # GET CPE DICT DATA
    # extract cpe data table
    cpes = open("bs4.html").read().split('<h2 id="Affected')
    cpeTable = cpes[1].split('<div class="header parbase section">')
    cpeTable = cpeTable[0]
    cpeTable = cpeTable.split('\n')

    # count number of CPEs
    numCPE = 0
    for line in cpeTable:
        if "</tr>" in line:
            numCPE += 1

    # get cpes and vendors
    products = ["" for i in range(numCPE)]
    products = parseHTML(products, cpeTable, "<tr>", 2, True)
    
    vendors = [0 for i in range(numCPE-1)]
    for j in range(len(products)):
        p = products[j].split()
        for i in range(len(p)):
            if p[i].lower() in name.lower():
                break
        vendors[j] = i
    # set vendor as parts of product before name
    for j in range(len(vendors)):
        if vendors[j] == 0:
            vendors[j] = name
        else:
            p = products[j].split()
            for i in range(vendors[j]):
                vendors[j] = ""
                vendors[j] += p[i]

    # get ending versions: take topmost from column
    endVers = ["" for i in range(numCPE)]
    endVers = parseHTML(endVers, cpeTable, "<tr>", 5, True)

    j=0
    for ver in endVers:
        ver = ver.split()
        ver = ver[0]
        endVers[j] = ver
        j += 1


    # get starting version if applicable
    hasStartVer = False
    for line in cveTable:
        if "Version" in line:
            hasStartVer = True
    if hasStartVer:
        startVers = ["" for i in range(numCVE-1)]
        startVers = parseHTML(startVers, cveTable, "CVE-", 3, False)

        j=0
        for ver in startVers:
            ver = ver.split()
            ver = ver[-1]
            startVers[j] = ver
            j += 1

    # CREATE DICT STRUCTURE GIVEN ABOVE DATA
    cpeList = []
    for i in range(numCPE-1):
        cpe = {
                "vendor" : vendors[i],
                "product" : name,
                "category" : "a",
                "versionEndIncluding" : endVers[i]
                }
        cpeList.append(cpe)
    cpeDict = {
            "cpe_list" : cpeList
            }

    # create dictionary of cves
    for i in range(numCVE-1):
        if hasStartVer:
            cpeList = []
            for j in range(numCPE-1):
                cpe = {
                        "vendor" : vendors[j],
                        "product" : name,
                        "category" : "a",
                        "versionStartIncluding" : startVers[i],
                        "versionEndIncluding" : endVers[j]
                        }
                cpeList.append(cpe)
            cpeDict = {
                    "cpe_list" : cpeList
                    }
            dct = {
                    "timestamp" : datetime.now().strftime("%m-%d-%YT%H:%M:%SZ"),
                    "published_date" : pubDate,
                    "id" : CVEID[i],
                    "url" : url,
                    "name" : name,
                    "description" : vulCats[i],
                    "cte" : cpeDict
                    }
        else:
            dct = {
                    "timestamp" : datetime.now().strftime("%m-%d-%YT%H:%M:%SZ"),
                    "published_date" : pubDate,
                    "id" : CVEID[i],
                    "url" : url,
                    "name" : name,
                    "description" : vulCats[i],
                    "cte" : cpeDict
                    }
        cveList.append(dct)

    # final output
    dictionary = {
            "source" : source,
            "type" : "vendor",
            "cves" : cveList
            }
    json_object = json.dumps(dictionary, indent=3)
    with open("output.json", "w") as outfile:
        outfile.write(json_object)

makeJSON("https://helpx.adobe.com/security/products/magento/apsb20-02.html")
