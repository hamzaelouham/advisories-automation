from datetime import datetime, timezone
import time
import requests
import logging
import pandas as pd
from bs4 import BeautifulSoup
from dateutil.relativedelta import relativedelta
import calendar
import re

# Configure the loggin
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

log = logging.getLogger("logger")

url = "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList"

headers = {
   "User-Agent":'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
}

last_month = datetime.now(timezone.utc) - relativedelta(months=1)

def get_json(url,count=1):
    try:
        log.info('Sending request to URL: %s', url)
        initialtime  = time.time()
        body = {
                'pageNumber': 0,
                'pageSize': count,
                'searchVal': '',
                'segment': 'VC',
                'sortInfo': {
                    'column': '',
                    'order': '',
                },
            }

        response = requests.post(url,headers=headers,json=body)
        
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
            return response.content.decode('utf-8')
        else:
            log.error('Unexpected status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - initialtime)
            return
    except requests.exceptions.RequestException as error:
        log.error('Error during request: %s', error)
        return

def get_last_day(y,m):
    return calendar.monthrange(y, m)[1]   

def scrape(link):
    data = {
        'Advisory ID': 'Advisory ID',
        'CVSSv3 Range': 'CVSSv3 Range',
        'Issue date': 'Issue date',
        'Updated on': 'Updated on',
        'CVE(s)': 'CVE(s)',
        'Synopsis': 'Synopsis',
        'Impacted Products' : '',
        'Introduction' : '',
        'Description' : '',
        'Known Attack Vectors' : '',
        'Resolution' : '',
        'Workarounds' : '',
        'Notes' : '',
        'Acknowledgements' : '',
        'Vulnerability Release link' : link,
        'Atos Advisory Annoucemnet ID' : '',
        'Atos Advisory Sent on' : '',
        'Atos Tested':'No',
        'Atos Recommendation':'Implement It'
    }
           
    html = get_html(link)
    soup = BeautifulSoup(html,features='html.parser')
    card = soup.find_all('div', class_="card-body")[1]
    text_content = card.get_text()
    table = card.find('table')
    labels = {
        'Advisory ID': 'Advisory ID',
        'CVSSv3 Range': 'CVSSv3 Range',
        'Issue date': 'Issue date',
        'Updated on': 'Updated on',
        'CVE(s)': 'CVE(s)',
        'Synopsis': 'Synopsis',
        }
   
    # Find all table rows
    rows = table.find_all('tr')
    for row in rows:
        cells = row.find_all('td')
        if len(cells) == 2:  # Make sure there are two cells: one for the label and one for the value
            label = cells[0].get_text(strip=True).replace(":", "")
            value = cells[1].get_text(strip=True)
            
            # Check if the label is in our predefined labels
            if label in labels:
                data[labels[label]] = value
          
    pro_pattern = re.compile(r"Impacted Products\s*(?:[:\-]?\s*)?(.*?)(?=\n\d+\.|\Z)", re.S)
    match_pro = pro_pattern.search(text_content)
    if match_pro:
        impacted_products_section = match_pro.group(1)
        data["Impacted Products"] = ', '.join([line.strip() for line in impacted_products_section.splitlines() if line.strip()])
    else:
        data["Impacted Products"] = ''
    intro_pattern = re.compile(r"Introduction\s*(?:[:\-]?\s*)?(.*?)(?=\n\d+\.|\Z)", re.S)
    match_intro = intro_pattern.search(text_content)
    if match_intro:
        data["Introduction"] = match_intro.group(1).strip().replace('\xa0', ' ')
    else:
        data["Introduction"] = ''
    know_pattern = re.compile( r"Description\s*(?:[:\-]?\s*)?(.*?)(?=\n(?:Known Attack Vectors|Resolution|Workarounds|Additional Documentation|Acknowledgements|Notes|Response Matrix):|\Z)", re.S)
    match_know = know_pattern.search(text_content)
    if match_know:
        data["Description"] = match_know.group(1).strip().replace('\xa0', ' ')
    else:
        data["Description"] = ''
    know_pattern = re.compile( r"Known Attack Vectors\s*(?:[:\-]?\s*)?(.*?)(?=\n(?:Resolution|Workarounds|Additional Documentation|Acknowledgements|Notes|Response Matrix):|\Z)", re.S)
    match_know = know_pattern.search(text_content)
    if match_know:
        data["Known Attack Vectors"] = match_know.group(1).strip().replace('\xa0', ' ')
    else:
        data["Known Attack Vectors"] = ''
    know_pattern = re.compile( r"Resolution\s*(?:[:\-]?\s*)?(.*?)(?=\n(?:Workarounds|Additional Documentation|Acknowledgements|Notes|Response Matrix):|\Z)", re.S)
    match_know = know_pattern.search(text_content)
    if match_know:
        data["Resolution"] = match_know.group(1).strip().replace('\xa0', ' ')
    else:
        data["Resolution"] = ''   
    know_pattern = re.compile( r"Workarounds\s*(?:[:\-]?\s*)?(.*?)(?=\n(?:Additional Documentation|Acknowledgements|Notes|Response Matrix):|\Z)", re.S)
    match_know = know_pattern.search(text_content)
    if match_know:
        data["Workarounds"] = match_know.group(1).strip().replace('\xa0', ' ')
    else:
        data["Workarounds"] = ''     
    know_pattern = re.compile( r"Acknowledgements\s*(?:[:\-]?\s*)?(.*?)(?=\n(?:Notes|Response Matrix):|\Z)", re.S)
    match_know = know_pattern.search(text_content)
    if match_know:
        data["Acknowledgements"] = match_know.group(1).strip().replace('\xa0', ' ')
    else:
        data["Acknowledgements"] = '' 
    know_pattern = re.compile( r"Notes\s*(?:[:\-]?\s*)?(.*?)(?=\n(?:Response Matrix):|\Z)", re.S)
    match_know = know_pattern.search(text_content)
    if match_know:
        data["Notes"] = match_know.group(1).strip().replace('\xa0', ' ')
    else:
        data["Notes"] = ''           
   
    return data    
                  
def extract(json):
    data = []
    year = int(last_month.strftime("%Y"))
    month = int(last_month.strftime("%m"))
    last_month_day = get_last_day(year, month)
    
    df = pd.json_normalize(json)

    start_date = f'{year}-{month:02d}-01'
    end_date = f'{year}-{month:02d}-{last_month_day:02d}'
    df['published'] = pd.to_datetime(df['published'], format="%d %B %Y")
    

    mask = (df['published'] > start_date) & (df['published'] <= end_date)
    df = df.loc[mask]
  
    for i, row in df.iterrows():
        data.append(scrape(row['notificationUrl']))
    return data
        

def save_to_excel(data):
     if data : 
        log.info('saving data into excel ...')
        df = pd.DataFrame(data)
        filename = str(last_month) + "-vmware-generated.xlsx"
        df.to_excel(filename, index=False)
        log.info('Done saving data ! ')    
     else:
        log.info('No data to save ! ') 

def main():

    initialtime  = time.time()
    count = get_json(url)['data']['pageInfo']['totalCount']
    json = get_json(url,count=count)['data']['list']
    data = extract(json)
    save_to_excel(data)
    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)
 
if __name__ == "__main__":
     main()





   

    











