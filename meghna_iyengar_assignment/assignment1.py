import requests
from bs4 import BeautifulSoup
from datetime import datetime
import dateutil
from dateutil import parser
import json

#removes escape characters from string
def remove (str):
    idx_n = str.find("\n")
    if(idx_n > 0):
        str = str[0:idx_n]
    idx_s = str.find("\u202f")
    if(idx_s > 0):
        str = str[0:idx_s]
    return str

#checks if a certain index of table contains a list of values
def in_range (row, col, table):
    table_rows = table.find_all("tr")
    table_cols = table_rows[row].find_all("td")
    cell = table_cols[col]
    if(len(cell.text.split(" ")) > 2):
        return True
    return False

#makes a list of the values at a certain column of the table 
def make_colList(idx, table, list):
    table_rows = table.find_all("tr")
    for i in range(1, len(table_rows)):
        cells = table_rows[i].find_all("td")
        ver = cells[idx].text.strip()        
        list.append(ver)
    return list

#makes a list of the values at a certain column of the table, and chooses first word
def make_colList_split(idx, table, list, str_idx):
    table_rows = table.find_all("tr")
    for i in range(1, len(table_rows)):
        cells = table_rows[i].find_all("td")
        ver = cells[idx].text.strip()
        #ver = remove_non_printable(ver)
        ver1 = ver.split(" ")
        #print(ver1)
        #print("hi")
        list.append(remove(ver1[str_idx]))
        
    return list  

#makes a list of the values at a certain column of the table
#used if table has a list of values at a certain cell
def make_colList_series(idx, table, list):
    table_rows = table.find_all("tr")
    for i in range(1, len(table_rows)):
        cells = table_rows[i].find_all("td")
        ver = cells[idx].text.strip()        
        clist = ver.split(" ")
        for j in range(len(clist)):
            clist[j] = clist[j].strip()
        list = list + clist
    return list

#makes a list of the values of at a certain column of the table
#used if table cells contain a range, and returns tuple of start and end values
def make_colList_range(idx, table, list):
    table_rows = table.find_all("tr")
    for i in range(1, len(table_rows)):
        cells = table_rows[i].find_all("td")
        if in_range(i, idx, table):
           ver = cells[idx].text.strip()
           #print(ver)
           ver_spl = ver.split(" ")
           start = (ver_spl[1]).strip()
           
           end = (ver_spl[len(ver_spl) - 1])
           tup = (remove(start), remove(end))
           list.append(tup)
        else:
            ver = cells[idx].text.strip()
            end = ver.split(" ")[1].strip()
            tup = (end)
            list.append(tup)
    return list

#finds index of a certain column in the table
def find_idx(name, table):
    rows = table.find_all("tr")
    cells = rows[0].find_all("td")
    for i in range(len(cells)):
        if (name in cells[i].text):
            return i
            
    return -1


url= input("Enter url here: ")

#gets current time
now = datetime.now()




#gets the html information from the url 
#using the requests and BeautifulSoup packages
response = requests.get(url)
soup = BeautifulSoup(response.content, 'html.parser')

#storing the 4 main tables
#numbered in order of appearance on website
tables = soup.find_all('div', class_ = 'table parbase section')
table1 = tables[0]
table2 = tables[1]
table3 = tables[2]
table4 = tables[3]


#getting published_date
table1_rows = table1.find_all("tr")
row1_cells = table1_rows[1].find_all("td")

published_date = (row1_cells[1].text).strip()


#gets the vendor from the Summary section of the website
text = soup.find_all("div", class_ = "text parbase section")
text1 = text[0].find_all("div", class_ = "text")
text2 = text1[0].find_all("p")
raw_text = text2[0].text

prod_vendor = raw_text.split(" ")[0]

#gets product name from given url

l = len("/products/")
product_idx = url.find("/products/")
pr_url = url[(l + product_idx):]
idx = pr_url.find("/")
product = pr_url[:idx]
product = product.replace("-", " ")

#formatting the published date to get ISO format
fixed = published_date.replace(",", " ")
date_list = fixed.split(" ")
date_str = date_list[1] + " " + date_list[0] + " " + date_list[3]
date = parser.parse(date_str)
pub_date = date.isoformat()


#to get CVE numbers
#finds index of CVE Numbers column
idx = find_idx("CVE Number", table4)

#if all CVEs are listed in one cell, uses one method to add them to a list
#else, just adds each cell's information from the CVE Number's column
needRangeCVE = False
if(in_range(1, idx, table4)):
    cve_list = make_colList_series(idx, table4, [])
    needRangeCVE = True
else:
    cve_list = make_colList(idx, table4, [])



#to get CPEs
#checks if each CVE has a range of CPEs, or if all share same CPEs
#if so, then adds a tuple of the start and end of range to the list CPEs
#else, just adds all versions to the list of CPEs

idx = find_idx("Affected Versions", table4) 
needRange = False

if(idx != -1):
    cpe_list = make_colList_range(idx, table4, [])
    needRange = True
else:
    cpe_list = make_colList_split(1, table2, [], 0)


#to get descriptions for each CVE
#if all CVEs have same description, then adds the same description 
# to list as many times as needed
if(needRangeCVE):
    desc_list = make_colList(0, table4, [])
    while(len(desc_list) != len(cve_list)):
        desc_list.append(desc_list[0])
else:
    desc_list = make_colList(0, table4, [])

#creating dictionaries to transform into a JSON file

j_dict = {}
cves = []


j_dict['source'] = prod_vendor
j_dict['type'] = "vendor"

#getting values from before
cve_list = cve_list
cpe_list = cpe_list
desc_list = desc_list

#loops through the CVEs and for each, creates its dictionary,
#including the CPE dictionaries for each

if(needRange):
    #if the CVE list contains ranges of CPEs then creates
    # a CPE dictionary with the corresponding range for each CVE
    #and adds the other entries to both dictionaries
    for i in range(len(cve_list)):
        cve_dict = {}
        cve_dict['timestamp'] = str(now)
        cve_dict['published_date'] = pub_date
        id = cve_list[i]
        cve_dict['id'] = id
        cve_dict['url'] = url
        cve_dict['name'] = product
        desc = desc_list[i]
        cve_dict['description'] = desc
        cpes = []
        cpe_dict = {}
        cpe_dict['vendor'] = prod_vendor 
        cpe_dict['product'] = product
        cpe_dict['category'] = 'a'
        item = cpe_list[i]
        if(type(cpe_list[i]) == tuple):
            versionStartIncluding = cpe_list[i][0]
            versionEndIncluding = cpe_list[i][1]
            cpe_dict['versionStartIncluding'] = versionStartIncluding
            cpe_dict['versionEndIncluding'] = versionEndIncluding
        else:
            versionEndIncluding = cpe_list[i]
            cpe_dict['versionEndIncluding'] = versionEndIncluding    
        cpes.append(cpe_dict)
        cve_dict["cpe-list"] = cpes
        cves.append(cve_dict)
else:
    #if all CVEs have same CPEs
    #this loops through CPEs and creates a dictionary
    #for each, and adds the list to each CVE dictionary
    #along with the other entries
    cpes = []
    for j in range(len(cpe_list)):
        cpe_dict = {}
        cpe_dict['vendor'] = prod_vendor
        cpe_dict['product'] = product
        cpe_dict['category'] = 'a'
        versionEndIncluding = cpe_list[j]
        cpe_dict['versionEndIncluding'] = versionEndIncluding
        cpes.append(cpe_dict)
            
    for i in range(len(cve_list)):
        cve_dict = {}
        cve_dict['timestamp'] = str(now)
        cve_dict['published_date'] = pub_date
        id = cve_list[i]
        cve_dict['id'] = id
        cve_dict['url'] = url
        cve_dict['name'] = product
        desc = desc_list[i]
        cve_dict['description'] = desc
        cve_dict['cpes_list'] = cpes
        cves.append(cve_dict)
    
 
j_dict['cves'] = cves

#writes to a file
with open("data.txt", "w") as outfile: 
    json.dump(j_dict, outfile, indent = 4)





















