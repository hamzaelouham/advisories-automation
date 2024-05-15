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
        response = requests.post(url,data={"segment":"VC","pageSize": 20},headers=headers)
        
        if response.status_code == 200 or response.status_code == 201:
            log.info('Request successful. Status code: %d. Time taken: %.2f seconds', response.status_code,time.time() - initialtime)
            return response.json()
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



























def main():

    initialtime  = time.time()
    url = "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList"

    
    print(get_json(url))

 
    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)

if __name__ == "__main__":
     main()










