from extra import *
from datetime import datetime
import time
import requests
from bs4 import BeautifulSoup
import pandas as pd
import json


def get_json(url):
    try:
        log.info('Sending request to URL: %s', url)
        initialtime  = time.time()
        response = requests.get(url,headers=headers)
        
        if response.status_code == 200 or response.status_code == 201:
            log.info('Request successful. Status code: %d. Time taken: %.2f seconds', response.status_code,time.time() - initialtime)
            return response.json()["data"]
        else:
            log.error('Unexpected status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - initialtime)
            return
    except requests.exceptions.RequestException as error:
        log.error('Error during request: %s', error)
        return

def get_html(url):
    try:
        log.info('Sending request to URL: %s', url)
        initialtime  = time.time()
        response = requests.get(url,headers=headers)
        
        if response.status_code == 200 or response.status_code == 201:
            log.info('Request successful. Status code: %d. Time taken: %.2f seconds', response.status_code,time.time() - initialtime)
            return response.content
        else:
            log.error('Unexpected status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - initialtime)
            return
    except requests.exceptions.RequestException as error:
        log.error('Error during request: %s', error)
        return

def scrape(item):
    _item = dict()
    _item["CVE"] = item["CVE"]
    _item["Pubdate"] = item["Pubdate"]
    _item["IssueDate"] = item["IssueDate"]
    _item["UpdatedOn"] = item["UpdatedOn"]
    _item["AdvisoryID"] = item["AdvisoryID"]
    _item["Synopsis"] = item["Synopsis"]
    _item["CVSSv3Range"] = item["CVSSv3Range"]
    advisoryURL = "https://www.vmware.com"+item["AdvisoryURL"]
    _item["VMware Security Advisory link"] = advisoryURL
   
    html = get_html(advisoryURL)
    soup = BeautifulSoup(html,features='html.parser')
    titles = [
              'Impacted Products',
              'Introduction',
              'Description',
              'Known Attack Vectors',
              'Resolution',
              'Workarounds',
              'Notes',
              'Acknowledgements'
             ]
    nodes = soup.find_all("div", class_="col-md-12 no-padd")

    for i in range(1,9):
        if i == 8:
            continue # Skip index 8
        temp_string = nodes[i].text
        temp_string = temp_string.strip()
        _item[titles[i-1]] = temp_string
      
    return _item  

   

def extract(items):
    advisories = []

    for item in items:
       _item = scrape(item)
       advisories.append(_item)    

    log.info('Start scraping data getting : %d advisory',len(advisories))
    return advisories


def transform(data):
     log.info('Starting saving data into excel /!\ ')
     df = pd.DataFrame(data)
     df.to_excel("data.xlsx", index=False)
     log.info('Done saving data into excel /!\ ')    

def getcurrentdate():
    return datetime.now().strftime('%Y-%m')

def main():

    currentdate = '2023-12'

    url = f"https://www.vmware.com/bin/vmware/getmodernizeadvisorieslist?resourcePath=/content/vmware/vmware-published-sites/us/security/advisories&searchText={currentdate}"
    
    rawdata = get_json(url)
    data = extract(rawdata)
    # html = extract(raw)
    transform(data)


if __name__ == "__main__":
     main()

