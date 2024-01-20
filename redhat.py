from datetime import datetime, timezone
import time
import requests
import logging
import pandas as pd
from bs4 import BeautifulSoup
import urllib.parse as url_tools 
from dateutil.relativedelta import relativedelta
import re


# Configure the loggin
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

log = logging.getLogger("logger")

headers = {
   "User-Agent":'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
}


def get_json(url):
    try:
        log.info('Sending request to target URL')
        initialtime  = time.time()
        response = requests.get(url,headers=headers)
        
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



def Query():
     last_month = datetime.now(timezone.utc) - relativedelta(months=1)
     month_before_last_month = datetime.now(timezone.utc) - relativedelta(months=2)
     qdate = f"{{!tag=ate}}portal_publication_date:([{month_before_last_month.strftime('%Y-%m-01T00:00:00.000Z')} TO {last_month.strftime('%Y-%m-01T00:00:00.000Z')}]) AND portal_product_filter:Red\ Hat\ Enterprise\ Linux|*|*|x86_64"
     
     return url_tools.quote_plus(qdate)

   

def extract(raw):
    data = []
    for r in raw:
        version_8_items = scrape(r, "8")
        version_9_items = scrape(r, "9")
        data.extend(version_8_items)
        data.extend(version_9_items)
    return data

def scrape(r, version):
     items = []
     
     html = get_html(r["view_uri"])
     
     soup = BeautifulSoup(html,features='html.parser')

     packages = soup.select_one('#packages')

     isfound = packages.find(string=f"Red Hat Enterprise Linux for x86_64 {version}")

     if isfound :   
      
      cves_element = soup.select_one("#cves").find("ul")
      cves_text = ', '.join([li.text.strip() for li in cves_element.find_all("li")])

      rpms = re.findall(r'\S+\.rpm',isfound.find_parent().find_next_sibling().text)

      for rpm in rpms:
          items.append({'OS':f'RHEL{version}','id':r['id'],'Advisory url': r["view_uri"],'Release Date': r['portal_publication_date'], 'vonder rating':r['portal_severity'], 'summary':r['portal_synopsis'].split(":")[1], 'Rpms':str(rpm), "CVEs": cves_text })
    
     return items  


def select(api): 
    return get_json(api)['response']['numFound']

def main():

    initialtime  = time.time()
    
    fq = Query()
    
    api = f"https://access.redhat.com/hydra/rest/search/kcs?q=Red+Hat+Enterprise+Linux&start=0&hl=true&hl.fl=abstract&hl.simple.pre=%253Cmark%253E&hl.simple.post=%253C%252Fmark%253E&fq=portal_advisory_type%3A%28%22Security+Advisory%22%29+AND+documentKind%3A%28%22Errata%22%29&facet=true&facet.mincount=1&rows=1&fl=id%2Cportal_severity%2Cportal_product_names%2Cportal_publication_date%2Cportal_synopsis%2Cview_uri%2CallTitle&sort=portal_publication_date+desc&p=1&facet.field=portal_severity&facet.field=portal_advisory_type&fq={fq}&facet.range.end=NOW&facet.range.start=NOW%2FYEAR-15YEARS&facet.range.gap=%2B1YEAR"   
        
    rows = select(api) 

    url = api.replace("rows=1", f"rows={rows}")
    
    raw_data = get_json(url)['response']['docs']
      
    log.info('getting %d rows  in: %.2f seconds', rows,time.time() - initialtime)
    # extracrt & scraping data 
    log.info('start Extract & scraping data')

    data = extract(raw_data)

    df = pd.DataFrame(data)

    df_sorted = df.sort_values(by='OS')
    # save scraped date into execl sheet
    df_sorted.to_excel('redhat-generated.xlsx', index=False) 
     
    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)

if __name__ == "__main__":
     main()

