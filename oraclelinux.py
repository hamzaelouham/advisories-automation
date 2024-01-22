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

    
           
def scrape(link, version):

    # Oracle Linux 9 (x86_64)
    html = get_html(link) 
    soup = BeautifulSoup(html,features='html.parser')
    aid = soup.find('li',string=lambda text: text and text.startswith('ELSA')).text.strip()
    container = soup.find('div', class_="mc10 mc10v6")
    summary = container.find('h2').text.strip().split(' - ')[1]
    tables = container.find_all('table')
    Type = tables[0].find_all('tr')[0].find_all('td')[1].text.strip()
    Severity = tables[0].find_all('tr')[1].find_all('td')[1].text.strip()
    Release_Date = tables[0].find_all('tr')[2].find_all('td')[1].text.strip()
    Cves =  ', '.join([td.text.strip() for td in tables[1].find_all("tr")])
    
    scraped = []
    
    start_row = soup.find('td',string=f"Oracle Linux {version} (x86_64)").find_parent()
    scraped.append({'OS':f'OL{version}','id':aid,'Advisory link': link,'type':Type ,'Release Date': Release_Date, 'vonder rating':Severity, 'summary':summary, 'Rpms': start_row.find_all('td')[1].text.strip(), "CVEs": Cves })
    rpms = start_row.find_all_next('tr')
    #Extract rpms from the target rows in table
    for rpm in rpms:
        
        scraped.append({'OS':f'OL{version}','id':aid,'Advisory link': link,'type':Type ,'Release Date': Release_Date, 'vonder rating':Severity, 'summary':summary, 'Rpms': rpm.find_all('td')[1].text.strip(), "CVEs": Cves })   

    return scraped
        

def extract(links):
    version = 9
    data = []
    for link in links:
       data.extend(scrape(link, version))
       
    return data

def get_links(html):
    
    links = []
    soup = BeautifulSoup(html,features='html.parser') 
    table = soup.find('table',class_="report-standard-alternatingrowcolors")
    rows = table.find_all("tr",class_="highlight-row")
    for row in rows :
       links.append("https://linux.oracle.com"+row.select_one('td[headers="ADVISORY_ID"] a')['href'])
    
    return links

def main():

    initialtime  = time.time()
    url = "https://linux.oracle.com/ords/f?p=105:21::::RP::"
    # max_rows = 1000
    # url_data  = f'https://linux.oracle.com/ords/f?p=105:21:103400541386218:pg_R_1213672130548773998:NO&pg_min_row=0&pg_max_rows={max_rows}&pg_rows_fetched=1000'
   
    html = get_html(url)
    links = get_links(html)
    data = extract(links)
    # save scraped date into execl sheet
    df = pd.DataFrame(data)
    df_sorted = df.sort_values(by=['OS', 'Release Date'])

    # save scraped date into execl sheet
    df_sorted.to_excel('OL-generated.xlsx', index=False)
    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)

if __name__ == "__main__":
     main()





