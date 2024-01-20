from datetime import datetime, timezone
import time
import requests
import pandas as pd
import logging
from bs4 import BeautifulSoup
import urllib.parse as url_tools 
from dateutil.relativedelta import relativedelta

# Configure the loggin
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

log = logging.getLogger("logger")

headers = {
   "User-Agent":'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
}



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

def scrape(html,tag='main'):
    soup = BeautifulSoup(html,features='html.parser')
    
    if tag == 'main':
       table = soup.find('table',class_="report-standard-alternatingrowcolors")
       html_rows = table.find_all("tr",class_="highlight-row")
       advisories = []
       item = {}
       for html_row in html_rows:
        #  item['advisoryUrl'] = html_row.select('td[headers="ADVISORY_ID"]')
            link = html_row.select_one('td[headers="ADVISORY_ID"] a')

            item = {
                        'url': "https://linux.oracle.com" +link['href'],
                        'Advisory':  link.text,
                        'Release_Date': html_row.select_one('td[headers="RELEASE_DATE"]').text
                    }
            advisories.append(item)
    
           
    else:
        print('scraping advisory page !')   

def main():

    initialtime  = time.time()
    
    url = "https://linux.oracle.com/ords/f?p=105:21::::RP::"
    max_rows = 1000
    
    url_data  = f'https://linux.oracle.com/ords/f?p=105:21:103400541386218:pg_R_1213672130548773998:NO&pg_min_row=0&pg_max_rows={max_rows}&pg_rows_fetched=1000'

    html = get_html(url)
    print(scrape(html)) 

    # save scraped date into execl sheet
   
   
    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)

if __name__ == "__main__":
     main()





