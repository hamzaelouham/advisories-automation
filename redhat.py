from datetime import datetime, timezone
import time
import requests
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

def  initRequest(fq):
     
     json = get_json(f"https://access.redhat.com/hydra/rest/search/kcs?q=Red+Hat+Enterprise+Linux&start=0&hl=true&hl.fl=abstract&hl.simple.pre=%253Cmark%253E&hl.simple.post=%253C%252Fmark%253E&fq=portal_advisory_type%3A%28%22Security+Advisory%22%29+AND+documentKind%3A%28%22Errata%22%29&facet=true&facet.mincount=1&rows=1&fl=id%2Cportal_severity%2Cportal_product_names%2Cportal_publication_date%2Cportal_synopsis%2Cview_uri%2CallTitle&sort=portal_publication_date+desc&p=1&facet.field=portal_severity&facet.field=portal_advisory_type&fq={fq}&facet.range.end=NOW&facet.range.start=NOW%2FYEAR-15YEARS&facet.range.gap=%2B1YEAR")

     return json["response"]["numFound"]


def generateQueryFilter():
        last_month = datetime.now(timezone.utc) - relativedelta(months=1)

        month_before_last_month = datetime.now(timezone.utc) - relativedelta(months=2)
        
        qdate = f"{{!tag=ate}}portal_publication_date:([{month_before_last_month.strftime('%Y-%m-01T00:00:00.000Z')} TO {last_month.strftime('%Y-%m-01T00:00:00.000Z')}]) AND portal_product_filter:*|*"
        
        return url_tools.quote_plus(qdate)


def extract(raw):
      for r in raw:
           scrape(r["view_uri"])   

def scrape(uri):
     html = get_html(uri)
     soup = BeautifulSoup(html,features='html.parser')
     print(soup.find("h2").text) 

def main():

    initialtime  = time.time()
    
    fq = generateQueryFilter()
    rows = initRequest(fq)
    
    log.info('getting %d rows  in: %.2f seconds',rows,time.time() - initialtime)
    
    api = f"https://access.redhat.com/hydra/rest/search/kcs?q=Red+Hat+Enterprise+Linux&start=0&hl=true&hl.fl=abstract&hl.simple.pre=%253Cmark%253E&hl.simple.post=%253C%252Fmark%253E&fq=portal_advisory_type%3A%28%22Security+Advisory%22%29+AND+documentKind%3A%28%22Errata%22%29&facet=true&facet.mincount=1&rows={rows}&fl=id%2Cportal_severity%2Cportal_product_names%2Cportal_publication_date%2Cportal_synopsis%2Cview_uri%2CallTitle&sort=portal_publication_date+desc&p=1&facet.field=portal_severity&facet.field=portal_advisory_type&fq={fq}&facet.range.end=NOW&facet.range.start=NOW%2FYEAR-15YEARS&facet.range.gap=%2B1YEAR"

    raw = get_json(api)["response"]["docs"]
    # extracrt & scraping data 
    log.info('start Extracrt & scraping data')
    extract(raw)


    # save scraped date into execl sheet
   
   
    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)

if __name__ == "__main__":
     main()

