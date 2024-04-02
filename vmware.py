from datetime import datetime
import time
import sys
import requests
import logging
from bs4 import BeautifulSoup
import pandas as pd

# Configure the loggin
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

log = logging.getLogger("logger")

headers = {
   "User-Agent":'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
}


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
            exit(1)
    except requests.exceptions.RequestException as error:
        log.error('Error during request: %s', error)
        exit(1)

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
            temp_string = nodes[i+1].text
            temp_string = temp_string.strip()
            _item[titles[i-1]] = temp_string
        else:
            temp_string = nodes[i].text
            temp_string = temp_string.strip()
            _item[titles[i-1]] = temp_string
    return _item  

def extract(items):
    advisories = []

    try: 
      for item in items:
       _item = scrape(item)
       advisories.append(_item)
       log.info('scraping  : %d advisory',len(advisories))

    except Exception as e:
        log.error('Error occured during scraping some pages : %s', e)
       
    finally:  
        log.info('%d advisory scraped ...',len(advisories))
    
    return advisories

def transform(data):
     if data : 
        log.info('saving data into excel ...')
        df = pd.DataFrame(data)
        filename = str(getcurrentdate()) + "-vmware-generated.xlsx"
        df.to_excel(filename, index=False)
        log.info('Done saving data ! ')    
     else:
        log.info('No data to save ! ') 
        exit(1)
def getcurrentdate():
     return datetime.now().strftime('%Y-%m')



def main():

    currentdate = str(sys.argv[1])
    initialtime  = time.time()
    url = f"https://www.vmware.com/bin/vmware/getmodernizeadvisorieslist?resourcePath=/content/vmware/vmware-published-sites/us/security/advisories&searchText={currentdate}"
    
    rawdata = get_json(url)
    data = extract(rawdata)
    transform(data)
 
    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)

if __name__ == "__main__":
     main()

