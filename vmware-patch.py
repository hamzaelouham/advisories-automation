from datetime import datetime, timezone, timedelta
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
last_month = datetime.now(timezone.utc) - relativedelta(months=0)
session = requests.Session()
url='https://support.broadcom.com/group/ecx/solutionfiles/-/solutionFiles/getSolutionFiles'

cookies = {
    'COOKIE_SUPPORT': 'true',
    'GUEST_LANGUAGE_ID': 'en_US',
    'OptanonAlertBoxClosed': '2024-04-19T09:49:29.524Z',
    'ac_client_user_id': 'ede8813e-f596-406a-9c20-418bba4910bf',
    '_gz_taid': '1714465997870951',
    'liferay-ingress-prd-us': '1727423633.118.43.459222|95b2e232c5e0be8e41c900a6b1ad87e6',
    'LFR_SESSION_STATE_20102': '1727425426386',
    'SAML_SP_SESSION_KEY': '_ede7bae0cef1f7cc9ae9209130e4dc4554e1daa2f6eb0710decadc772020',
    'JSESSIONID': 'D51ECCB06E358D8F24F896D4D028A941',
    'OptanonConsent': 'isGpcEnabled=0&datestamp=Fri+Sep+27+2024+09%3A37%3A54+GMT%2B0100+(GMT%2B01%3A00)&version=202301.2.0&isIABGlobal=false&hosts=&consentId=93cf45f4-3b74-4206-a615-fb0c26db8f81&interactionCount=1&landingPath=NotLandingPage&groups=1%3A1%2C3%3A1%2C2%3A0%2C4%3A0&geolocation=ES%3BMD&AwaitingReconsent=false',
    'LFR_SESSION_STATE_71940356': '1727426276912',
}
  

headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
}



params = {
    'page': '0',
    'size': '50',
}

json_data = {
    'displayGroup': 'VMware vSphere - Standard',
    'release': '7.0',
    'os': '',
    'solutionOS': '',
    'component': '',
    'searchVal': '',
    'orderCol': 'CNFDATE',
    'orderSeq': 'DESC',
    'toDate': '',
}



def get_json(url,payload):
    try:
        log.info('Sending request to target URL')
        initialtime  = time.time()
        response = session.post( 
        url,
        params=params,
        cookies=cookies,
        headers=headers,
        json=payload
        )
        
        if response.status_code == 200 or response.status_code == 201:
            log.info('Request successful. Status code: %d. Time taken: %.2f seconds', response.status_code,time.time() - initialtime)
            return response.json()
        else:
            log.error('Unexpected status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - initialtime)
            return
    except requests.exceptions.RequestException as error:
        log.error('Error during request: %s', error)
        return
    
def get_last_day(year, month):
    if month == 12:
        return 31
    next_month = datetime(year, month + 1, 1)
    return (next_month - timedelta(days=1)).day

def extract(json):
    data = []
    # Define year and month from the global variable
    year = last_month.year
    month = last_month.month
    
    # Get the last day of the previous month
    last_month_day = get_last_day(year, month)
    
    # Normalize JSON data into a DataFrame
    df = pd.json_normalize(json['data']['solutions'])
    
    # Convert the 'date' column to datetime with the correct format
    df['published'] = pd.to_datetime(df['date'], format="%m/%d/%Y")
    
    # Define start and end dates for the last month, make them timezone naive
    start_date = datetime(year, month, 1)  # Naive datetime
    end_date = datetime(year, month, last_month_day)  # Naive datetime
    
    # Convert start_date and end_date to pandas Timestamps (naive)
    start_date = pd.Timestamp(start_date)
    end_date = pd.Timestamp(end_date)
    
    df['published'] = pd.to_datetime(df['published'])
    
    # Filter the DataFrame for patches released last month
    df_filtered = df[(df['published'] >= start_date) & (df['published'] <= end_date)]
    # If the DataFrame is empty, print a message
    if df_filtered.empty:
        print("No data found for the last month.")
    # Extract and print relevant data
    for _, row in df_filtered.iterrows():
        scraped_data = scrape(row)
        data.append(scraped_data)
    return data
def extract_Generic_product_name(release_name):
    # Remove any trailing parts that are likely not part of the product name
    release_name = release_name.split(' ')[0]  # Remove any part after the first space if it exists
    release_name = release_name.split('-')[0]  # Remove any part after the first dash if it exists
    
    return release_name
def extract_product_name(release_name):
    # Remove any trailing parts that are likely not part of the product name
    release_name = release_name.split(' ')[0]  # Remove any part after the first space if it exists
    release_name = release_name.split('-')[0]  # Remove any part after the first dash if it exists
    
    # Special handling for 'ESXi'
    if release_name == 'ESXi':
        return 'ESXi (Embedded and Installable)'
    
    return release_name

def save_to_excel(data):
    if data:
        log.info('Saving data into Excel...')
        df = pd.DataFrame(data)
        filename = f"{last_month.strftime('%Y-%m')}-vmware-patch-generated.xlsx"
        df.to_excel(filename, index=False)
        log.info('Done saving data!')
    else:
        log.info('No data to save!')   

def scrape(row):
    link = f"https://support.broadcom.com/web/ecx/solutiondetails?patchId={row['patchId']}"
    api_url ='https://support.broadcom.com/web/ecx/solutiondetails/-/solutionDetails/getSolutionDetailsDownloadForPatch'
    ljson = get_json(api_url,{'patchId': row['patchId'] })
    data = { 'Generic Product Name': extract_Generic_product_name(row['title']),
             'Release Name': row['title'],
             'Product Name': extract_product_name(row['title']),
             'Release Date': row['date'],
             'System Impact':'',
             'Build': ljson['data']['patchDTO']['buildNumber'],
             'Version': ljson['data']['patchDTO']['patchNumber'],
             'Patch Category/ Patch Severity': row['type'],	
             'Download Filename': ljson['data']['patchDTO']['files'][0]["fileName"],	
             'vCenter Reboot Required':'',	
             'ESXi Host Reboot Required':'',	
             'Virtual Machine Migration or Shutdown Required':'',
             'Atos Advisory Annoucemnet ID':'',	
             'Atos Advisory Sent on':'' ,
             'Atos Tested':'NO',
             'Atos Recommendation':'Yes',	
             'VMware Patch Release Link': link,	
             'OEM General Support Staus':''
             }																												
    return data    
       
          



json = get_json(url,json_data)


data = extract(json)
save_to_excel(data)