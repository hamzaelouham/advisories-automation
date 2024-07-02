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
            return response.content
        else:
            log.error('Unexpected status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - initialtime)
            return
    except requests.exceptions.RequestException as error:
        log.error('Error during request: %s', error)
        return

def get_last_day(y,m):
    return calendar.monthrange(y, m)[1]   
 
def scrape_page(row):
    html = get_html(row['notificationUrl'])
    soup = BeautifulSoup(html,features='html.parser')
    card = soup.find_all('div', class_="card-body")[1]
    table = card.find('table')
    ul = card.find('ul')
    tr = table.find_all('tr')
    html_str = html.decode('utf-8')
    pattern = r'<h2>(.*?)</h2>\s*<p><b>Description:</b>\s*(.*?)</p>\s*<p><b>Known Attack Vectors:</b>\s*(.*?)</p>\s*<p><b>Workarounds:</b>\s*(.*?)</p>\s*<p><b>Notes:</b>\s*(.*?)</p>\s*<p><b>Acknowledgements:</b>\s*(.*?)</p>'

# Find all matches in the HTML content
    matches = re.findall(pattern, html_str, re.DOTALL)

# Iterate over matches and print extracted information
    for match in matches:
        print("Vulnerability:", match[0])
        print("Description:", match[1])
        print("Known Attack Vectors:", match[2])
        print("Workarounds:", match[3])
        print("Notes:", match[4])
        print("Acknowledgements:", match[5])
        print()

    # pattern = r'<h2>(.*?)</h2>\s*<p><b>Description:</b>\s*(.*?)</p>\s*<p><b>Known Attack Vectors:</b>\s*(.*?)</p>\s*<p><b>Workarounds:</b>\s*(.*?)</p>\s*<p><b>Notes:</b>\s*(.*?)</p>\s*<p><b>Acknowledgements:</b>\s*(.*?)</p>'
    # matches = re.findall(pattern, html, re.DOTALL)
    # # Impacted_Products = ""
    # # if ul is not None:
    # #     Impacted_Products =  ', '.join([li.text.strip() for li in ul.find_all("li")])
    
    # for match in matches:
    #     print("Vulnerability:", match[0])
    #     print("Description:", match[1])
    #     print("Known Attack Vectors:", match[2])
    #     print("Workarounds:", match[3])
    #     print("Notes:", match[4])
    #     print("Acknowledgements:", match[5])
    #     print()
    return {
            'VMware Security Advisory': tr[0].find_all('td')[1].get_text(strip=True),	
            'CVSSv3 Range' : tr[2].find_all('td')[1].get_text(strip=True),
            'Issue Date'   : tr[4].find_all('td')[1].get_text(strip=True),
            'Updated On'   : tr[5].find_all('td')[1].get_text(strip=True),	
            'CVE'          : row['affectedCve'] ,
            'Synopsis'     : tr[3].find_all('td')[1].get_text(strip=True),	
            # 'Impacted Products': Impacted_Products,
            'Introduction' : card.find('p').text.strip(),
            'VMware Security Advisory link': row['notificationUrl']
        }
 
   




def extract(json):
    # data = []
    # year = int(last_month.strftime("%Y"))
    # month = int(last_month.strftime("%m"))
    # last_month_day = get_last_day(year,month)
    # df = pd.json_normalize(json)
    # start_date =  f'{year}-{month}-01'
    # end_date = f'{year}-{month}-{last_month_day}'

    # df['published'] = pd.to_datetime(df['published'], format="%d %B %Y")
    # mask = (df['field_pub_date'] > start_date) & (df['field_pub_date'] <= end_date)
    # df = df.loc[mask]
   
    # for index, row in df.iterrows():
    #     data.extend(scrape_page(row))
    # return data

    data = []
    year = int(last_month.strftime("%Y"))
    month = int(last_month.strftime("%m"))
    last_month_day = get_last_day(year, month)
    
    df = pd.json_normalize(json)

    start_date = f'{year}-{month:02d}-01'
    end_date = f'{year}-{month:02d}-{last_month_day:02d}'
    df['published'] = pd.to_datetime(df['published'], format="%d %B %Y")
    
    # Ensure date range strings are in datetime format for comparison
    # start_date_dt = pd.to_datetime(start_date)
    # end_date_dt = pd.to_datetime(end_date)

    mask = (df['published'] > start_date) & (df['published'] <= end_date)
    df = df.loc[mask]
  
    for index, row in df.iterrows():
        data.append(scrape_page(row))
        print(row['notificationUrl'])
    
    return data







 












def main():

    initialtime  = time.time()
    url = "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList"

    
    count = get_json(url)['data']['pageInfo']['totalCount']
    json = get_json(url,count=count)['data']['list']
    extract(json)

 
    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)

if __name__ == "__main__":
     main()










