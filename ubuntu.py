from datetime import datetime, timezone
import time
import requests
import logging
import pandas as pd
from bs4 import BeautifulSoup
import urllib.parse as url_tools 
from dateutil.relativedelta import relativedelta
import re


# Configure the loggin
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

log = logging.getLogger("logger")

http = requests.Session()

url = "https://ubuntu.com/security/notices"

headers = {
   "User-Agent":'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
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

def scrape_page(link):
    print(link)

def extract(): 
    html = get_html(url)
    log.info('start Extract & scraping data')
    soup = BeautifulSoup(html,features='html.parser')
    articles = soup.select('article', _class="notice")
    for article in articles:
        scrape_page(url+article.find('a')['href'])
        

def main():
    initialtime  = time.time()
    # extracrt & scraping data 
    extract()
    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)
   
   
    

if __name__ == "__main__":
     main()