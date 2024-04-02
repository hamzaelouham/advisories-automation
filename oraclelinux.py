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

    
# Oracle Linux 9 (x86_64)
           
def scrape(link, version):

    html = get_html(link) 
    soup = BeautifulSoup(html,features='html.parser')
    aid = soup.find('li',string=lambda text: text and (text.startswith('ELEA') or text.startswith('ELSA')or text.startswith('ELBA'))).text.strip()
    container = soup.find('div', class_="mc10 mc10v6")
    summary = container.find('h2').text.strip().split(' - ')[1]
    tables = container.find_all('table')
    Type = tables[0].find_all('tr')[0].find_all('td')[1].text.strip()
    Severity = tables[0].find_all('tr')[1].find_all('td')[1].text.strip()
    Release_Date = tables[0].find_all('tr')[2].find_all('td')[1].text.strip()
    Cves =  ', '.join([td.text.strip() for td in tables[1].find_all("tr")])
    category = "General Advisory" if Type == 'BUG' else "Security Advisory"
    scraped = []
    start_row = None
    
    if soup.find('td',string=f"Oracle Linux {version} (x86_64)"):
        start_row = soup.find('td',string=f"Oracle Linux {version} (x86_64)").find_parent()
        # scraped.append({'OS':f'OL{version}','id':aid,'Advisory link': link,'type':Type ,'Release Date': Release_Date, 'vonder rating':Severity, 'summary':summary, 'Rpms': start_row.find_all('td')[1].text.strip(), "CVEs": Cves })
        scraped.append({
                        'OS': f'OL{version}',
                        'Release Date': Release_Date,
                        'Category': category,
                        'Vendor Category': Type,
                        'Bulletin ID / Patch ID': aid, 
                        'RPMs': start_row.find_all('td')[1].text.strip(),
                        'CVEs':Cves ,
                        'Bulletin Title and Executive Summary':summary,
                        'Vendor Rating': Severity,
                        'Atos Rating':'N/A',
                        'Tested':'NO',
                        'Exception':'NO',
                        'Announcement links': link
            })
        
        rpms = start_row.find_all_next('tr')
        #Extract rpms from the target rows in table
        for rpm in rpms:
            rpm_elements = rpm.find_all('td')
            # rpm.find_all('td')[1].text.strip()
            if len(rpm_elements) >= 2:
                rpms_value = rpm_elements[1].text.strip()
            else:
                rpms_value = "N/A"
              
            scraped.append({
                        'OS': f'OL{version}',
                        'Release Date': Release_Date,
                        'Category': category,
                         'Vendor Category': Type,
                        'Bulletin ID / Patch ID': aid, 
                        'RPMs':str(rpms_value),
                        'CVEs':Cves ,
                        'Bulletin Title and Executive Summary':summary,
                        'Vendor Rating': Severity,
                        'Atos Rating':'N/A',
                        'Tested':'NO',
                        'Exception':'NO',
                        'Announcement links': link
            })
    return scraped
        

def extract(links):
    rlink = 1
    data = []
    for link in links:
       print(f'Getting : {rlink}/{len(links)} row')
       data.extend(scrape(link, 7))
       data.extend(scrape(link, 8))
       rlink = rlink + 1    
    return data
       

def get_links(html):
    
    links = []
    soup = BeautifulSoup(html,features='html.parser') 
    table = soup.find('table',class_="report-standard-alternatingrowcolors")
    rows = table.find_all("tr",class_="highlight-row")
    for row in rows :
       links.append("https://linux.oracle.com" + row.select_one('td[headers="ADVISORY_ID"] a')['href'])
    
    return links

def main():

    initialtime  = time.time()
    
    max_rows = str(sys.argv[1])
    url = f'https://linux.oracle.com/ords/f?p=105:21:3414613945235:pg_R_1213672130548773998:NO&pg_min_row=1&pg_max_rows={max_rows}&pg_rows_fetched={max_rows}'
    html = get_html(url)
    links = get_links(html)
    data = extract(links)
    # save scraped date into execl sheet
    df = pd.DataFrame(data)
    last_month = pd.Timestamp('today').month - 1
    df['Release Date'] = pd.to_datetime(df['Release Date'], format='%Y-%m-%d')
    filtered_df = df[df['Release Date'].dt.month == last_month]
    # save scraped date into execl sheet
    filtered_df.to_excel('OL-generated.xlsx', index=False)

    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)

if __name__ == "__main__":
     main()





