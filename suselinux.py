from datetime import datetime, timezone
import time
import requests
import logging
import pandas as pd
from bs4 import BeautifulSoup
from dateutil.relativedelta import relativedelta
import re

# Configure the loggin
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

log = logging.getLogger("logger")

http = requests.Session()

headers = {
   "User-Agent":'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
}

patching_date = datetime.now(timezone.utc) - relativedelta(months=1)
uri = f'https://lists.suse.com/pipermail/sle-updates/{patching_date.year}-{patching_date.strftime("%B")}/'
url = uri+'date.html'

SLES = {
    "SLES 15":"SUSE Linux Enterprise Server 15 SP5",
    "SLES 15":"SUSE Linux Enterprise Module for Basesystem 15-SP5",
    "SLES 15":"Basesystem Module 15-SP5",
    "SLES 12":"SUSE Linux Enterprise Server 12 SP5",
    "SLES 12":"SUSE Linux Enterprise Module for Basesystem 12-SP5",
    "SLES 12":"Basesystem Module 12-SP5",
    "SLES 12":"SUSE Linux Enterprise Server for SAP Applications 12 SP5"
}


def get_html(url):
    try:
        log.info('Sending request to URL: %s', url)
        initialtime  = time.time()
        response = http.get(url,headers=headers)
        
        if response.status_code == 200 or response.status_code == 201:
            log.info('Request successful. Status code: %d. Time taken: %.2f seconds', response.status_code,time.time() - initialtime)
            return response.content
        else:
            log.error('Unexpected status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - initialtime)
            return
    except requests.exceptions.RequestException as error:
        log.error('Error during request: %s', error)
        return

def extract(): 
    html = get_html(url)
    log.info('start Extract & scraping data')
    soup = BeautifulSoup(html,features='html.parser')
    ul = soup.find_all("ul")[1]
    # data = []
    for li in ul.find_all("li"):
        link = uri + li.find('a')['href']
        scrape_page(link)
        # data.append()

    # return data

def scrape_page(link):
    html = get_html(link)
    soup = BeautifulSoup(html,features='html.parser')
    title = soup.find("h1").text.strip().split(':')
    id = f'{title[0]}:{title[1]}'
    severity = title[2]
    summary = title[3]
    category = "Security Advisory" if title[0].startswith('SUSE-SU') else "General Advisory"
    issue_date = datetime.strptime(soup.find("i").text.strip(), "%a %b %d %H:%M:%S %Z %Y").strftime("%d-%m-%Y")  
    content = soup.find("pre").text
    cve_pattern = r"CVE-\d{4}-\d+"
    
    if list(dict.fromkeys(re.findall(cve_pattern, content))):
        cves = ', '.join(list(dict.fromkeys(re.findall(cve_pattern, content))))
    else:
        cves = "N/A"
       
    
    print(cves)





def trans_to_Execl(data):
     df = pd.DataFrame(data)
     df.to_excel('suse-generated.xlsx', index=False) 


def main():
    initialtime  = time.time()
   
    
    # extracrt & scraping data 
  
    extract()
    # trans_to_Execl(scrape(html))
    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)


if __name__ == "__main__":
     main()











