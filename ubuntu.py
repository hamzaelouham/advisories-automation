from datetime import datetime, timezone
import time
import requests
import logging
import pandas as pd
from bs4 import BeautifulSoup, UnicodeDammit
import urllib.parse as url_tools 
from dateutil.relativedelta import relativedelta
import re


# Configure the loggin
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

log = logging.getLogger("logger")

http = requests.Session()

url = "https://ubuntu.com"

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

def parse_date2(date_str):
    return datetime.strptime(date_str, '%d %B %Y').date() 
def parse_date(date_str):
    return datetime.strptime(date_str, '%d %B %Y').strftime('%d/%m/%Y')

def fetch_security_notices(offset):
    page_url = url + f"/security/notices?offset={offset}"
    
    try:
        log.info('Sending request to URL: %s', page_url)
        initialtime  = time.time()
        response = http.get(page_url,headers=headers)
        
        if response.status_code == 200 or response.status_code == 201:
            log.info('Request successful. Status code: %d. Time taken: %.2f seconds', response.status_code,time.time() - initialtime)
            return response.content
        else:
            log.error('Unexpected status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - initialtime)
            return
    except requests.exceptions.RequestException as error:
        log.error('Error during request: %s', error)
        return

def extract_links(date='1/04/2024', current_offset=0):
    links = []
    html = fetch_security_notices(current_offset)
    soup = BeautifulSoup(html, features='html.parser')
    articles = soup.select('article', class_='notice')  # Corrected the class name
    for article in articles:
        pub_date = article.find('p', class_="u-no-margin u-no-padding--top")
        if pub_date:
            parsed_date = parse_date2(pub_date.text.strip())
            if parsed_date >= datetime(2024, 4, 1).date():
                links.append(url + article.find('a')['href'])
            else:
                return links    
    next_offset = current_offset + 10        
    return links + extract_links(date,next_offset) 
          
# def extract_pages(links):
#     packages_data = []
#     for link in links:
#         html = get_html(link)   
#         soup = BeautifulSoup(UnicodeDammit(html,["latin-1", "iso-8859-1", "windows-1251"]).unicode_markup, features='html.parser')
#         section = soup.find('section',class_="p-strip--suru-topped")
#         # id = section
#         # .text.strip().split(':')[0]
#         print(section)
#         # print(link)
        
        
        

def main():
    initialtime  = time.time()
    # extracrt & scraping data 
    links = extract_links()
    # extract_pages(links)
    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)
   
   
    

if __name__ == "__main__":
     main()