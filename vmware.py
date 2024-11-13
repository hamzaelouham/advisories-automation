from datetime import datetime, timezone
import time
import requests
import logging
import pandas as pd
from bs4 import BeautifulSoup
from dateutil.relativedelta import relativedelta
import calendar
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger("logger")

url = "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList"
headers = {
    "User-Agent": 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
}

last_month = datetime.now(timezone.utc)  - relativedelta(months=1)

def fetch_data(url, method='get', json_data=None):
    try:
        log.info('Sending %s request to URL: %s', method.upper(), url)
        start_time = time.time()
        
        if method == 'post':
            response = requests.post(url, headers=headers, json=json_data)
        else:
            response = requests.get(url, headers=headers)
        
        response.raise_for_status()
        
        log.info('Request successful. Status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - start_time)
        return response.json() if method == 'post' else response.content.decode('utf-8')
        
    except requests.exceptions.RequestException as error:
        log.error('Error during request: %s', error)
        return None

def get_last_day(year, month):
    return calendar.monthrange(year, month)[1]

def scrape(row):
    link = row['notificationUrl']
    data = {
        'Advisory ID': 'Advisory ID',
        'Severity':row['severity'],
        'CVSSv3 Range': 'CVSSv3 Range',
        'Issue date': 'Issue date',
        'Updated on': 'Updated on',
        'CVE(s)': row['affectedCve'],
        'Synopsis': 'Synopsis',
        'Impacted Products': '',
        'Introduction': '',
        'Description': '',
        'Known Attack Vectors': '',
        'Resolution': '',
        'Workarounds': '',
        'Notes': '',
        'Acknowledgements': '',
        'Vulnerability Release link': link,
        'Atos Advisory Annoucemnet ID': '',
        'Atos Advisory Sent on': '',
        'Atos Tested': 'No',
        'Atos Recommendation': 'Implement It'
    }
    
    html = fetch_data(link, method='get')
    if not html:
        return data

    soup = BeautifulSoup(html, features='html.parser')
    card = soup.find_all('div', class_="card-body")[1]
    text_content = card.get_text()
    table = card.find('table')
    
    # Extract table data
    labels = {
        'Advisory ID': 'Advisory ID',
        'CVSSv3 Range': 'CVSSv3 Range',
        'Issue date': 'Issue date',
        'Updated on': 'Updated on',
        'Synopsis': 'Synopsis'
    }
    
    for row in table.find_all('tr'):
        cells = row.find_all('td')
        if len(cells) == 2:
            label = cells[0].get_text(strip=True).replace(":", "")
            value = cells[1].get_text(strip=True)
            if label in labels:
                data[labels[label]] = value

    # Extract additional content
    patterns = {
        "Impacted Products": r"Impacted Products\s*(?:[:\-]?\s*)?(.*?)(?=\n\d+\.|\Z)",
        "Introduction": r"Introduction\s*(?:[:\-]?\s*)?(.*?)(?=\n\d+\.|\Z)",
        "Description": r"Description\s*(?:[:\-]?\s*)?(.*?)(?=\n(?:Known Attack Vectors|Resolution|Workarounds|Additional Documentation|Acknowledgements|Notes|Response Matrix):|\Z)",
        "Known Attack Vectors": r"Known Attack Vectors\s*(?:[:\-]?\s*)?(.*?)(?=\n(?:Resolution|Workarounds|Additional Documentation|Acknowledgements|Notes|Response Matrix):|\Z)",
        "Resolution": r"Resolution\s*(?:[:\-]?\s*)?(.*?)(?=\n(?:Workarounds|Additional Documentation|Acknowledgements|Notes|Response Matrix):|\Z)",
        "Workarounds": r"Workarounds\s*(?:[:\-]?\s*)?(.*?)(?=\n(?:Additional Documentation|Acknowledgements|Notes|Response Matrix):|\Z)",
        "Acknowledgements": r"Acknowledgements\s*(?:[:\-]?\s*)?(.*?)(?=\n(?:Notes|Response Matrix):|\Z)",
        "Notes": r"Notes\s*(?:[:\-]?\s*)?(.*?)(?=\n(?:Response Matrix):|\Z)"
    }
    
    for key, pattern in patterns.items():
        match = re.search(pattern, text_content, re.S)
        if match:
            data[key] = match.group(1).strip().replace('\xa0', ' ')
        else:
            data[key] = ''
    
    return data

def extract(json):
    data = []
    year = last_month.year
    month = last_month.month
    last_month_day = get_last_day(year, month)
    
    df = pd.json_normalize(json)
    df['published'] = pd.to_datetime(df['published'], format="%d %B %Y")
    
    start_date = f'{year}-{month:02d}-01'
    end_date = f'{year}-{month:02d}-{last_month_day:02d}'
    
    df = df[(df['published'] > start_date) & (df['published'] <= end_date)]
    
    for _, row in df.iterrows():
        scraped_data = scrape(row)
        data.append(scraped_data)
    
    return data

def save_to_excel(data):
    if data:
        log.info('Saving data into Excel...')
        df = pd.DataFrame(data)
        filename = f"{last_month.strftime('%Y-%m')}-vmware-generated.xlsx"
        df.to_excel(filename, index=False)
        log.info('Done saving data!')
    else:
        log.info('No data to save!')

def main():
    start_time = time.time()
    
    json_data = fetch_data(url, method='post', json_data={
        'pageNumber': 0,
        'pageSize': 1,
        'searchVal': '',
        'segment': 'VC',
        'sortInfo': {'column': '', 'order': ''}
    })
    
    if json_data:
        total_count = json_data['data']['pageInfo']['totalCount']
        all_json = fetch_data(url, method='post', json_data={
            'pageNumber': 0,
            'pageSize': total_count,
            'searchVal': '',
            'segment': 'VC',
            'sortInfo': {'column': '', 'order': ''}
        })
        
        if all_json:
            data = extract(all_json['data']['list'])
            save_to_excel(data)
    
    log.info('Successfully finished. Time taken: %.2f seconds', time.time() - start_time)

if __name__ == "__main__":
    main()
