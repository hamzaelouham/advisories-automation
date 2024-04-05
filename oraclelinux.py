from datetime import datetime, timezone
import time
import requests 
import pandas as pd
import logging
from bs4 import BeautifulSoup
import sys
# import urllib.parse as url_tools 
# from dateutil.relativedelta import relativedelta

# Configure the loggin
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger("logger")
request = requests.Session()
headers = {
   "User-Agent":'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
}

oraclelinux = {
    "OL7_aarch64" :"Oracle Linux 7 (aarch64)",
    "OL7_x86_64"  :"Oracle Linux 7 (x86_64)",
    "OL8_aarch64" :"Oracle Linux 8 (aarch64)",
    "OL8_x86_64"  :"Oracle Linux 8 (x86_64)",
}

def get_html(url): 
    
    try:
        log.info('Sending request to URL: %s', url)
        initialtime  = time.time()
        response = request.get(url,headers=headers)
        
        if response.status_code == 200 or response.status_code == 201:
            log.info('Request successful. Status code: %d. Time taken: %.2f seconds', response.status_code,time.time() - initialtime)
            return response.content
        else:
            log.error('Unexpected status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - initialtime)
            return
    except request.exceptions.RequestException as error:
        log.error('Error during request: %s', error)
        return


def scrape_single_page(link):
    data = []
    html = get_html(link) 
    soup = BeautifulSoup(html,features='html.parser')
    id = soup.find('li',string=lambda text: text and (text.startswith('ELEA') or text.startswith('ELSA')or text.startswith('ELBA'))).text.strip()
    container = soup.find('div', class_="mc10 mc10v6")
    summary = container.find('h2').text.strip().split(' - ')[1]
    tables = container.find_all('table')
    Type = tables[0].find_all('tr')[0].find_all('td')[1].text.strip()
    Severity = tables[0].find_all('tr')[1].find_all('td')[1].text.strip()
    Release_Date = tables[0].find_all('tr')[2].find_all('td')[1].text.strip()
    Cves =  ', '.join([td.text.strip() for td in tables[1].find_all("tr")])
    category = "General Advisory" if Type == 'BUG' else "Security Advisory"
       
    for product in oraclelinux:
       element_found = soup.find('td',string=oraclelinux[product]) 

       if element_found: 
          
          start_row = element_found.find_parent() 
          data.append({
                        'OS': product,
                        'Release Date': Release_Date,
                        'Category': category,
                        'Vendor Category': Type,
                        'Bulletin ID / Patch ID': id, 
                        'RPMs': start_row.find_all('td')[1].text.strip(),
                        'CVEs':Cves ,
                        'Bulletin Title and Executive Summary':summary,
                        'Vendor Rating': Severity,
                        'Atos Rating':'N/A',
                        'Tested':'NO',
                        'Exception':'NO',
                        'Announcement links': link
            })
       
          for tr in start_row.find_all_next('tr'):
              if len(tr) >= 2: 
                 data.append({
                        'OS': product,
                        'Release Date': Release_Date,
                        'Category': category,
                        'Vendor Category': Type,
                        'Bulletin ID / Patch ID': id, 
                        'RPMs': tr.find_all('td')[1].text.strip(),
                        'CVEs':Cves ,
                        'Bulletin Title and Executive Summary':summary,
                        'Vendor Rating': Severity,
                        'Atos Rating':'N/A',
                        'Tested':'NO',
                        'Exception':'NO',
                        'Announcement links': link
                    })
              
              else:
                 break
    return data

def scrape_pages(url):
    
    html = get_html(url)
    soup = BeautifulSoup(html,features='html.parser') 
    table = soup.find('table',class_="report-standard-alternatingrowcolors")
    rows = table.find_all("tr",class_="highlight-row")
    data = []

    for row in rows :
       data.append(scrape_single_page("https://linux.oracle.com" + row.select_one('td[headers="ADVISORY_ID"] a')['href'])) 
    return data


def main():

    initialtime  = time.time()
    max_rows = str(sys.argv[1])
    url = f'https://linux.oracle.com/ords/f?p=105:21:3414613945235:pg_R_1213672130548773998:NO&pg_min_row=1&pg_max_rows={max_rows}&pg_rows_fetched={max_rows}'
    data = scrape_pages(url)
  
    df = pd.DataFrame(data)
    last_month = pd.Timestamp('today').month - 1
    df['Release Date'] = pd.to_datetime(df['Release Date'], format='%Y-%m-%d')
    filtered_df = df[df['Release Date'].dt.month == last_month]
    # save scraped date into execl sheet
    filtered_df.to_excel('OL-generated.xlsx', index=False)
    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)
    
if __name__ == "__main__":
     main()





