from bs4 import BeautifulSoup
import requests
from datetime import datetime
import json
import re
import sys

from parsing_constants import *

# Parses the affected product versions from a vulnerability.
# Input: affected_table, a BeautifulSoup element of the table containing
#    information on the affected products.
def parse_affected_versions(affected_table):
  rows = affected_table.find_all('tr')
  cpes = []
  vers_idx = 1    # by default, let's assume the 2nd column contains version info
  for i in range(len(rows)):
    row = rows[i]
    if i == 0:
      cols = row.find_all('th')
      if not cols:
        cols = row.find_all('td')
      cols = [ele.text.strip() for ele in cols]
      for j in range(len(cols)):
        if 'version' in cols[j] or 'Version' in cols[j]:
          # column index of affected versions
          vers_idx = j
    else:
      cols = row.find_all('td')
      cols = [ele.text.strip() for ele in cols]
      cpe = {"category" : "a"}
      cpe["vendor"] = 'adobe'
      words = cols[0].lower().replace("adobe", '').split(' ')
      cpe["product"] = '_'.join(words)

      if "earlier" in cols[vers_idx] or "below" in cols[vers_idx]:
        ver_str = cols[vers_idx].split()[0]
        cpe["versionEndIncluding"] = ver_str
      else:
        if not cols[vers_idx]:
          continue
        vers = [float(v) for v in cols[vers_idx].split('\n')]
        cpe["versionEndIncluding"] = str(max(vers))
        cpe["versionStartIncluding"] = str(min(vers))
      cpes.append(cpe)
  return {'cpe_list' : cpes}

# Primary function for parsing vulnerability metrics given a URL.
# Input: url, the string URL of the page in question.
def parse_vulnerability_metrics(url):
  page = requests.get(url)
  if not page:
    raise RuntimeError("Could not access provided URL.")
  soup = BeautifulSoup(page.content, 'html.parser')

  # find the product name; for Adobe Security Bulletin, these seem to all
  #  be located in the page-description class div
  name_div = soup.find('div', {"class" : "page-description"})
  prod_name = re.split("for ", name_div.text, flags=re.IGNORECASE)[1]
  prod_name = prod_name.split(' |')[0].replace("Adobe ", "")

  # grab all tables from the page
  tables = soup.find_all("tbody")
  if len(tables) != 4:
    raise RuntimeError("Didn't find the expected number of tables on this page.")
  [date_table, affected_table, _, vuln_table] = tables

  # find publish date: it will be the second-to-last entry
  pub_str = date_table.find_all('td')[-2].text.strip()
  pub_date = datetime.strptime(pub_str, '%B %d, %Y').strftime(DT_FORMAT)

  now = datetime.now().strftime(DT_FORMAT)
  cpes = parse_affected_versions(affected_table)

  # find vulnerability details (ID and description)
  vuln_rows = vuln_table.find_all('tr')
  cves = []

  for i in range(len(vuln_rows)):
    row = vuln_rows[i]
    if i == 0:
      cols = row.find_all('td')
      if not cols:
        cols = row.find_all('th')
      cols = [ele.text.strip() for ele in cols]
      headers = cols
    else:
      cols = row.find_all('td')
      cols = [ele.text.strip() for ele in cols]
      cve = {'timestamp' : now, 'published_date' : pub_date, 'url' : url, 'cpes' : cpes, 'name' : prod_name}
      for j in range(len(cols)):
        if headers[j] in NAME_MAPPINGS:
          if NAME_MAPPINGS[headers[j]] == "description":
            cve[NAME_MAPPINGS[headers[j]]] = cols[j].lower()
          else:
            cve[NAME_MAPPINGS[headers[j]]] = cols[j]
      cves.append(cve)
  return cves

# Some sample pages to parse. Maps desired output JSON file name to URL.
samples = {
  "sample1" : "https://helpx.adobe.com/security/products/magento/apsb20-02.html",
  "sample2" : "https://helpx.adobe.com/security/products/experience-manager/apsb20-01.html",
  "sample3" : "https://helpx.adobe.com/security/products/acrobat/apsb19-55.html",
  "sample4" : "https://helpx.adobe.com/security/products/acrobat/apsb20-13.html",
  "sample5" : "https://helpx.adobe.com/security/products/flash-player/apsb20-06.html",
  "sample6" : "https://helpx.adobe.com/security/products/creative-cloud/apsb20-11.html",
  "sample7" : "https://helpx.adobe.com/security/products/acrobat/apsb20-05.html",
  "sample8" : "https://helpx.adobe.com/security/products/Digital-Editions/apsb20-23.html",
  "sample9" : "https://helpx.adobe.com/security/products/acrobat/apsb19-02.html",

}

if __name__ == "__main__":
  args = sys.argv
  if '-i' in args:
    url = args[args.index('-i') + 1]
    outf = "sample"
    if '-o' in args:
      outf = args[args.index('-o') + 1]
    outf = outf
    sample = {"source" : "adobe", "type" : "vendor"}
    try:
      sample["cves"] = parse_vulnerability_metrics(url)
    except RuntimeError as e:
      print("Failed in parsing " + url + ":", str(e))
      sys.exit()

    with open(outf + '.json', 'w') as fp:
      json.dump(sample, fp, indent=2)
      print("Successfully parsed " + url + ", results written to " + outf + ".json")

  else:
    # by default, just parse the samples above
    for name in samples:
      sample = {"source" : "adobe", "type" : "vendor"}
      try:
        sample["cves"] = parse_vulnerability_metrics(samples[name])
      except RuntimeError as e:
        print("Failed in parsing " + samples[name] + ":", str(e))
        continue

      with open(name + '.json', 'w') as fp:
        json.dump(sample, fp, indent=2)
        print("Successfully parsed " + samples[name] + ", results written to " + name + ".json")