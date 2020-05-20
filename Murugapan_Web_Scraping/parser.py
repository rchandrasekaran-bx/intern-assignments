from bs4 import BeautifulSoup
import requests
from datetime import datetime
import json
import os

#have the input text file with url list in the current working directory
#os.chdir('C:/ms cs/Web Scraping')

#description - read from a text file with a list of different webpages in seperate lines into a list
#input - text file with urls in different lines
#output - list of url
def getURLs(file):
    urlList = []
    with open(file, 'r') as f:
        for url in f:
            urlList.append(url)
    return urlList

#description - formatDate scraps published date from web page and converts it into iso format
#input - date as string
#output - equivalent date in iso
def formatDate(date):
    date = date.replace(",", "")
    formatedDate = date.split()
    day = formatedDate[1]
    formatedDate[1] = formatedDate[0]
    formatedDate[0] = day
    date = ' '.join(formatedDate)
    datetimeObject = datetime.strptime(date, '%d %B %Y')
    return datetimeObject.strftime('%Y-%m-%dT%H:%M:%S.%f%z')

#description - find the CVE in dict format for each row in the vulnerablity table
#input - a row in vulnerablity table in the url, idColumn - column number of cve id in vulnerablity table
#input - descriptionColumn - column number of vulnerablity category in vulnerablity table
#input - affectedVersion = None if affected version is not in vulnerablity table, else the column number of it in vulnerablity table
#output - void - populates the currentCVE - global dict
def buildCVE(vulnerablity, idColumn, descriptionColumn, affectedVersion):
    timestamp = datetime.utcnow().isoformat() #current timestamp in iso format
    currentCVE['Timestamp'] = timestamp

    #observation - all the given help pages of adobe had 4 tables
    #table 1 - bulletin info with id, published date and priority
    #table 2 - affected version with product, version and platform
    #table 3 - solution with product, version and platform
    #table 4 - vulnerablity details with category and cve numbers
    tables = soup.findAll('div', class_ = 'table parbase section') #fetch all tables

    bulletinInfo = tables[0] #scrap published date and format it to iso 
    datePublished = bulletinInfo.findAll('tr')[1].findAll('td')[1].text
    publishedDate = formatDate(datePublished)
    currentCVE['Published Date'] = publishedDate

    #print(vulnerablityDetails.prettify())
    #cve id is in the idColumn of vulnerablity table
    id = vulnerablity.findAll('td')[idColumn].text.replace(u'\xa0', u'').replace(u'\n', u'')
    currentCVE['ID'] = id

    url = 'https://helpx.adobe.com/security/products/magento/apsb20-02.html'
    currentCVE['URL'] = url

    #product name is obtained from page description class
    name = soup.find('div', class_ = 'page-description').text.strip().split('|')[0].split('for')[1]
    currentCVE['Name'] = name

    #category is in the descriptionColumn of vulnerablity table
    description = vulnerablity.findAll('td')[descriptionColumn].text
    currentCVE['Description'] = description.replace(u'\xa0', u'').replace(u'\n', u'')

    #info about each affected version is dumped into cpe list
    cpeList = buildCPEList(vulnerablity, affectedVersion, tables) #call the buildCPEList method with tables and the affectedVersions
    currentCVE['CPEs'] = {}
    currentCVE['CPEs']['CPE_List'] = cpeList
    CVEs.append(currentCVE.copy())
    return

#description - returns cpeList for each row in vulnerablity table
#input - a row in the vulnerablity table
#input - affectedVersion = None if affected version is not in vulnerablity table, else the column number of it in vulnerablity table
#input - tables - list of all tables in the url
#output - cpeList for a row in vulnerablity table
def buildCPEList(vulnerablity, affectedVersion, tables):
    cpeList = []
    #affected version info is fetched from affected version table
    if(affectedVersion == None):
        columnNames = tables[1].findAll('tr')[0].text.strip().split('\n') #find the column number of version name and number in the affected versions table
        versionId = 0
        productId = 0
        for i in range(len(columnNames)):
            if("Version" in columnNames[i]):
                versionId = i
            if("Product" in columnNames[i]):
                productId = i
        affectedVersions = tables[1].findAll('tr')[1:]
        for version in affectedVersions: #fetch vendor, product, category and versionEnd for all affected versions as a list and return the list
            version = version.findAll('td')
            current = {}
            current['Vendor'] = version[productId].text.split()[0]
            current['Product'] = version[productId].text.replace(u'\xa0', u'').replace(u'\n', u'')
            current['Category'] = 'a'
            current['VersionEndIncluding'] = version[versionId].text.split()[0].replace(u'\xa0', u'').replace(u'\n', u'')
            cpeList.append(current)
            
    #affected version info is fetched from vulnerablity table
    else:
        version = vulnerablity.findAll('td')[affectedVersion].text.strip().replace(u'\xa0', u'').replace(u' ', u'').split('\n')
        current = {}
        affectedVersions = tables[1].findAll('tr')[1:]
        for product in affectedVersions:
            product = product.findAll('td')
            current = {}
            current['Vendor'] = product[0].text.split()[0]
            current['Product'] = product[0].text.replace(u'\xa0', u'').replace(u'\n', u'')
        current['Category'] = 'a'
        current['VersionStartIncluding'] = version[0]
        current['VersionEndIncluding'] = version[-1]
        cpeList.append(current)
        
    return cpeList
        
#description - called from main method - extracts the vulnerablity metrices into a dict
#output - void - populates global result which has the vulnerablity metrices
def buildResult():
    #populate the CVE info starting from the vulnerablity table
    tables = soup.findAll('div', class_ = 'table parbase section')
    vulnerablityDetails = tables[3]
    columnNames = vulnerablityDetails.findAll('tr')[0].findAll('td')
    #from the column names identify the column number of cve number and vulnerablity category
    #check whether affected versions is presnt in the vulnerablity table, if so find the column number and store it in affectedVersion else set it to None
    affectedVersion = None
    for i in range(len(columnNames)):
        if("CVE Number" in columnNames[i].text):
            idColumn = i
        if("Vulnerability Category" in columnNames[i].text):
            descriptionColumn = i
        if("Affected Versions" in columnNames[i].text):
            affectedVersion = i
    vulnerablityDetails = vulnerablityDetails.findAll('tr')[1:]
    for vulnerablity in vulnerablityDetails: #for each row in vulnerablity table call the buildCVE method to populate the result
        buildCVE(vulnerablity, idColumn, descriptionColumn, affectedVersion)

    result['Source'] = URL.split('//')[-1].split('/')[0].split('.')[-2] #source is obtained from domain name of url
    result['Type'] = 'Vendor'
    result['CVEs'] = CVEs
    return


###driver block
urlList = getURLs('urls.txt') #text file with list of urls
#URL = 'https://helpx.adobe.com/security/products/magento/apsb20-02.html'
#URL = 'https://helpx.adobe.com/security/products/experience-manager/apsb20-01.html'

for url in urlList:
    URL = str(url).replace(u'\n', u'') #for each url, build soup object by requests and lxml parser
    print(url)
    outputFileName = URL.split('/')[-1].split('.')[0] + '.txt'

    source = requests.get(URL).text
    soup = BeautifulSoup(source, 'lxml') 
    #print(soup.prettify())
    
    result = {} #global variables
    CVEs = []
    currentCVE = {}

    buildResult() #call buildResult

    output = json.dumps(result, indent = 4) #the json is dumped into output text files matching the name of input url
    print(output)
    with open(outputFileName, 'w') as f:
        f.write(output)
