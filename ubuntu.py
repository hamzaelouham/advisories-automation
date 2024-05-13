from datetime import datetime, timezone
import time
import requests
import logging
import pandas as pd
from bs4 import BeautifulSoup
from dateutil.relativedelta import relativedelta
import os



# Configure the loggin
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

log = logging.getLogger("logger")

http = requests.Session()

url = "https://ubuntu.com"

ubuntu = ('Ubuntu 22.04', 'Ubuntu 20.04')

patching_date = datetime.now(timezone.utc) - relativedelta(months=1)

headers = {
   "User-Agent":'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
}

def get_html(url):
    try:
        log.info('Sending request to URL: %s', url)
        initialtime  = time.time()
        response = http.get(url,headers=headers)
        
        if response.status_code == 200 or response.status_code == 201:
            log.info('Request successful. Status code: %d. Time taken: %.2f seconds', response.status_code,time.time() - initialtime)
            return response.content
        else:
            log.error('Unexpected status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - initialtime)
            return
    except requests.exceptions.RequestException as error:
        log.error('Error during request: %s', error)
        return

def parse_date2(date_str):
    return datetime.strptime(date_str, '%d %B %Y').date() 
def parse_date(date_str):
    return datetime.strptime(date_str, '%d %B %Y').strftime('%d/%m/%Y')

def fetch_security_notices(offset):
    page_url = url + f"/security/notices?offset={offset}"
    
    try:
        log.info('Sending request to URL: %s', page_url)
        initialtime  = time.time()
        response = http.get(page_url,headers=headers)
        
        if response.status_code == 200 or response.status_code == 201:
            log.info('Request successful. Status code: %d. Time taken: %.2f seconds', response.status_code,time.time() - initialtime)
            return response.content
        else:
            log.error('Unexpected status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - initialtime)
            return
    except requests.exceptions.RequestException as error:
        log.error('Error during request: %s', error)
        return

def extract_links(date='1/04/2024', current_offset=0):
    links = []
    html = fetch_security_notices(current_offset)
    soup = BeautifulSoup(html, features='lxml')
    articles = soup.select('article', class_='notice')  # Corrected the class name
    for article in articles:
        pub_date = article.find('p', class_="u-no-margin u-no-padding--top")
        if pub_date:
            parsed_date = parse_date2(pub_date.text.strip())
            if parsed_date >= datetime(2024, 4, 1).date():
                links.append(url + article.find('a')['href'])
            else:
                return links    
    next_offset = current_offset + 10        
    return links + extract_links(date,next_offset) 


def extract_pages(links):
    big_data = []
    for link in links:
        html = get_html(link)  
        # ["latin-1", "iso-8859-1", "windows-1251"]).unicode_markup ,from_encoding=html.encoding
        soup = BeautifulSoup(html,features='lxml')
        section = soup.find('section',class_="p-strip--suru-topped")
        title = products = None
        if section:
            div_fixed = section.find('div', class_="u-fixed-width")
            rows = section.find_all('div', class_="row")
            if div_fixed and rows:
               title_element = div_fixed.find("h1")
               issue_date = parse_date(div_fixed.find('p',class_="p-muted-heading").text.strip()) 
            #    products = [li.text.strip()  for li in rows[0].find('ul',class_="p-inline-list").find_all("li",class_="p-inline-list__item") ]
               if title_element:
                    title = title_element.text.strip()
                   
               col = rows[1].find('div',class_="col-8")
               ref = rows[2].find('div',class_="col-8")
               Cves =  ', '.join([li.text.strip() for li in ref.find("ul")])
               products = [ p for p in col.find_all("h5") ]
               for product in products:
                    for ub in ubuntu:
                      if product.text.strip().startswith(ub):
                        ul = product.find_next()
                                            
                        for li in  ul.find_all('li',class_="p-list__item"):
                           deblink = li.find_all('a')[1]["href"]
                           if not deblink.startswith('/pro'):
                              big_data.extend(scrape({ 
                                    'OS' : ub,
                                    'Release Date': issue_date,
                                    'Bulletin ID / Patch ID' : title.split(':')[0],
                                    'deblink': li.find_all('a')[1]["href"] ,
                                    'CVEs': Cves,
                                    'Bulletin Title and Executive Summary':title.split(':')[1],
                                      'Announcement links': link
                              })) 
    return big_data

                
def get_amd_link(link):
    html = get_html(link)  
    soup = BeautifulSoup(html,features='lxml')
    div = soup.find('div', class_='two-column-list')
    package_page_link = None 
    if div : 
       dt = div.find('dt', string='Urgency:')
       if dt :
        severity = dt.find_next_sibling('dd').text.strip().split(' ')[0]
       
    div = soup.find('div', id='source-builds')
    if div:
       atags = div.find_all('a')
       for atag in atags:
           if 'amd64' in atag.get_text():
               package_page_link = 'https://launchpad.net/'+atag.get('href')
           
    return package_page_link, severity           
            

def scrape(_data):
    data = []
    
    # Attempt to retrieve package_page_link and severity
    package_page_link, severity = get_amd_link(_data["deblink"])

    if package_page_link is not None :  # Proceed only if package_page_link is valid
        try:
            html = get_html(package_page_link)  
            soup = BeautifulSoup(html, features='lxml')        
            div = soup.find('div', id="files")
            
            if div: 
                ul = div.find('ul')
                for li in ul.find_all('li'):
                    rpm_name = li.find('a').get_text()
                    data.append({
                        'OS': _data['OS'],
                        'Release Date': _data['Release Date'],
                        'Category': "Security Advisory",
                        'Vendor Category': "Security Advisory",
                        'Bulletin ID / Patch ID': _data['Bulletin ID / Patch ID'], 
                        'RPMs': rpm_name,
                        'CVEs': _data['CVEs'],
                        'Bulletin Title and Executive Summary': _data['Bulletin Title and Executive Summary'],
                        'Vendor Rating': severity,
                        'Atos Rating': 'N/A',
                        'Tested': 'NO',
                        'Exception': 'NO',
                        'Announcement links': _data['Announcement links']
                    })
        except Exception as e:
            # Handle any exceptions that might occur during scraping
            log.warning('Error scraping data from %s: %s', package_page_link, e)
    
    return data
            

def save_data(data):
     df = pd.DataFrame(data)
     df["Release Date"] = pd.to_datetime(df['Release Date'],format='%d-%m-%Y').dt.date
     folder = 'collected'
     df_sorted = df.sort_values(by='OS')
     file_name = f'Ubuntu-Generated-Month-{patching_date.strftime("%B")}.xlsx'
     path = os.path.join(folder, file_name)
     if not os.path.exists(folder):
       os.makedirs(folder)
     df_sorted.to_excel(path, index=False) 
        
        

def main():
    initialtime  = time.time()
    # extracrt & scraping data 
    links = extract_links()
    big_data = extract_pages(links)
    save_data(big_data)
    
    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)

if __name__ == "__main__":
     main()