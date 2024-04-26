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

last_month = datetime.now(timezone.utc) - relativedelta(months=1)

RHEL_versions = {
    "RHEL 7":"Red Hat Enterprise Linux Server 7",
    "RHEL 8":"Red Hat Enterprise Linux for x86_64 8",
    "RHEL 9":"Red Hat Enterprise Linux for x86_64 9",
    "RHEL8.2 sap hana":"Red Hat Enterprise Linux for x86_64 - Update Services for SAP Solutions 8.2",
    "RHEL8.4 sap hana":"Red Hat Enterprise Linux for x86_64 - Update Services for SAP Solutions 8.4",
    "RHEL8.6 sap hana":"Red Hat Enterprise Linux for x86_64 - Update Services for SAP Solutions 8.6",
    "RHEL8.8 sap hana":"Red Hat Enterprise Linux for x86_64 - Update Services for SAP Solutions 8.8"
}


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



def Query():
    #  last_month = datetime.now(timezone.utc) - relativedelta(months=1)
     current_month = datetime.now(timezone.utc) 
    
     qdate = f"{{!tag=ate}}portal_publication_date:([{last_month.strftime('%Y-%m-01T00:00:00.000Z')} TO {current_month.strftime('%Y-%m-01T00:00:00.000Z')}]) AND portal_product_filter:Red\ Hat\ Enterprise\ Linux|*|*|x86_64"
    
     return url_tools.quote_plus(qdate)

def is_valide_link(link):
    return "https://access.redhat.com/errata/" in link 

def extract(raw):
    data = []
    for r in raw:
        data.extend(scrape(r))
    return data
      
       
   

def scrape(r):
    items = []
    if is_valide_link(r['view_uri']):
        html = get_html(r["view_uri"])
        soup = BeautifulSoup(html,features='html.parser')
        packages = soup.select_one('#packages')
        issue_date = datetime.strptime(soup.select_one('.details').find("dd").text, '%Y-%m-%d').strftime('%d-%m-%Y')
        vendor_category = soup.select_one('.print-single').find("h1").text.split("-")[2]
       
        if vendor_category.strip() == "Security Advisory":
           category = vendor_category
        else: 
            category = "General Advisory" 

        vendor_rating = r['portal_severity'] if r['portal_severity'] else 'N/A'
        
        if r['portal_severity'] == "None":
            summary =  r['portal_synopsis']
        else:
            summary =r['portal_synopsis'].split(":")[1]
        
        for product in RHEL_versions:

            if packages:
                isfound = packages.find(string=RHEL_versions[product])
                if isfound :   
                    cves_element = soup.select_one("#cves").find("ul")
                    if cves_element:
                        cves_text = ', '.join([li.text.strip() for li in cves_element.find_all("li")])
                    else:   
                        cves_text = 'None' 
                    rpms = re.findall(r'\S+\.rpm',isfound.find_parent().find_next_sibling().text)
                    for rpm in rpms:
                        #   items.append({'OS':f'RHEL{version}','id':r['id'],'Advisory url': r["view_uri"],'Release Date': r['portal_publication_date'], 'vonder rating':r['portal_severity'], 'summary':r['portal_synopsis'].split(":")[1], 'Rpms':str(rpm), "CVEs": cves_text })
                        items.append({
                            'OS': product,
                            'Release Date': issue_date,
                            'Category': category,
                            'Vendor Category': vendor_category,
                            'Bulletin ID / Patch ID': r['id'], 
                            'RPMs':str(rpm),
                            'CVEs':cves_text ,
                            'Bulletin Title and Executive Summary': summary,
                            'Vendor Rating': vendor_rating,
                            'Atos Rating':'N/A',
                            'Tested':'NO',
                            'Exception':'NO',
                            'Announcement links':r["view_uri"]
                        })
    else:
        log.warning('invalid link ! :  %s', r["view_uri"])        
    return items  

def save_data(data):
    df = pd.DataFrame(data)
    folder = 'collected'
    df_sorted = df.sort_values(by='OS')
    file_name = f'Redhat-Generated-Month-{last_month .strftime("%B")}.xlsx'
    path = os.path.join(folder, file_name)
    if not os.path.exists(folder):
       os.makedirs(folder)
    df_sorted.to_excel(path, index=False) 

    # save scraped date into execl sheet

def select(api): 
    return get_json(api)['response']['numFound']

def main():

    initialtime  = time.time()
    
    fq = Query()
    
    api = f"https://access.redhat.com/hydra/rest/search/kcs?q=Red+Hat+Enterprise+Linux&start=0&hl=true&hl.fl=abstract&hl.simple.pre=%253Cmark%253E&hl.simple.post=%253C%252Fmark%253E&facet=true&facet.mincount=1&rows=1&fl=id%2Cportal_severity%2Cportal_product_names%2Cportal_publication_date%2Cportal_synopsis%2Cview_uri%2CallTitle&sort=portal_publication_date+desc&p=1&facet.field=portal_severity&facet.field=portal_advisory_type&fq={fq}&facet.range.end=NOW&facet.range.start=NOW%2FYEAR-15YEARS&facet.range.gap=%2B1YEAR"   
       
    rows = select(api) 

    url = api.replace("rows=1", f"rows={rows}")
    
    raw_data = get_json(url)['response']['docs']
      
    log.info('getting %d rows  in: %.2f seconds', rows,time.time() - initialtime)
    # extracrt & scraping data 
    log.info('start Extract & scraping data')

    data = extract(raw_data)
    save_data(data)     

    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)

if __name__ == "__main__":
     main()

