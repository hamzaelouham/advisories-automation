from datetime import datetime, timezone
import time
import requests
import logging
import pandas as pd
from bs4 import BeautifulSoup
import urllib.parse as url_tools 
from dateutil.relativedelta import relativedelta
import re
import os

# Configure the loggin
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

log = logging.getLogger("logger")

session = requests.Session()

headers = {
   "User-Agent":'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
}

url = "https://www.ibm.com/support/pages/"

last_month = datetime.now(timezone.utc) - relativedelta(months=1)

def get_html(url):
    try:
        log.info('Sending request to URL: %s', url)
        initialtime  = time.time()
        response = session.get(url,headers=headers)
        
        if response.status_code == 200 or response.status_code == 201:
            log.info('Request successful. Status code: %d. Time taken: %.2f seconds', response.status_code,time.time() - initialtime)
            return response.content
        else:
            log.error('Unexpected status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - initialtime)
            return
    except requests.exceptions.RequestException as error:
        log.error('Error during request: %s', error)
        return


def get_json(url):
    try:
        log.info('Sending request to target URL')
        initialtime  = time.time()
        response = session.get(url,headers=headers)
        
        if response.status_code == 200 or response.status_code == 201:
            log.info('Request successful. Status code: %d. Time taken: %.2f seconds', response.status_code,time.time() - initialtime)
            return response.json()
        else:
            log.error('Unexpected status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - initialtime)
            return
    except requests.exceptions.RequestException as error:
        log.error('Error during request: %s', error)
        return

def extract(json):
    data = []
    df = pd.json_normalize(json)

    start_date = f'{last_month.strftime("%Y")}-{last_month.strftime("%m")}-01'
    end_date = f'{last_month.strftime("%Y")}-{last_month.strftime("%m")}-31'
    df['field_pub_date'] = pd.to_datetime(df['field_pub_date'])
    mask = (df['field_pub_date'] > start_date) & (df['field_pub_date'] <= end_date)
    df = df.loc[mask]
   
    for index, row in df.iterrows():
        data.extend(scrape_page(row))
    return data    
       

def scrape_page(r):
    items = []
    link = url + f"node/{r['nid']}"
    html = get_html(link)
    soup = BeautifulSoup(html,features='html.parser')
    ibm_container = soup.find('div', class_="ibm-container ibm-alternate")
    category = ibm_container.find('h3', class_="ibm-h4 ibm-bold ibm-northstart-product-documentation-title").text.split(' ')[0].strip()
    summary = ibm_container.find("p",class_="ibm-northstart-documentation-information-data").text.strip()
    table = soup.find_all("table")[0]
    tr = table.find_all('tr')
    for i in range(1,len(tr)):
        
        items.append({
            'OS': tr[i].text,
            'Release Date': r['field_pub_date'].date(),
            'Category': category,
            'Vendor Category': category,
            'Bulletin ID / Patch ID':  r["title"], 
            'RPMs': link,
            'CVEs':r["field_cve_id"] ,
            'Bulletin Title and Executive Summary': summary,
            'Vendor Rating': r["field_cvss_base_score"],
            'Atos Rating':'N/A',
            'Tested':'NO',
            'Exception':'NO',
            'Announcement links': link
        })
    return items

def save_data(data):
    df = pd.DataFrame(data)
    df["Release Date"] = pd.to_datetime(df['Release Date'], dayfirst=True).dt.date
    folder = 'collected'
    df_sorted = df.sort_values(by='OS')
    file_name = f'AIX-Generated-Month-{last_month.strftime("%B")}.xlsx'
    path = os.path.join(folder, file_name)
    if not os.path.exists(folder):
       os.makedirs(folder)
    df_sorted.to_excel(path, index=False) 

def main():
    initialtime  = time.time()

    json = get_json(url + "securityapp/api/search/?q=AIX")['results']

    log.info('start Extract & scraping data')
    data = extract(json)
    save_data(data)

    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)

if __name__ == "__main__":
     main()
