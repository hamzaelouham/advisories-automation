from dateutil.relativedelta import relativedelta
from datetime import datetime, timezone
from bs4 import BeautifulSoup
import pandas as pd
import calendar
import requests
import logging
import asyncio
import httpx
import time
import os
import re


# Configure the loggin
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

log = logging.getLogger("logger")

http = requests.Session()

url = "https://ubuntu.com"

ubuntu = ('Ubuntu 22.04', 'Ubuntu 20.04')

patching_date = datetime.now(timezone.utc) - relativedelta(months=1)

# headers = {
#    "User-Agent":'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36'
# }

headers = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "accept-language": "en-US,en;q=0.9,fr;q=0.8,fr-FR;q=0.7,en-GB;q=0.6",
    "cache-control": "max-age=0",
    "priority": "u=0, i",
    "sec-ch-ua": "\"Chromium\";v=\"124\", \"Microsoft Edge\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1"
}
async def  _get_html(url):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            if response.status_code == 200:
                return response.text
            else:
                print(f"Request failed with status code: {response.status_code}")
    except httpx.RequestError as exc:
        print(f"An error occurred during the request: {exc}")

def get_html(url):
    try:
        log.info('Sending request to URL: %s', url)
        initialtime  = time.time()
        response = http.get(url,headers=headers,allow_redirects=True)
        
        if response.status_code == 200 or response.status_code == 201:
            log.info('Request successful. Status code: %d. Time taken: %.2f seconds', response.status_code,time.time() - initialtime)
            return response.content
        else:
            log.error('Unexpected status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - initialtime)
            return
    except requests.exceptions.RequestException as error:
        log.error('Error during request: %s', error)
        return

def skip_link(link):
    if re.search(r'/LSN-\d+-\d+$', link):
            return True
    return False

def is_within_month(parsed_date, patching_date):
     patching_month_start = datetime(patching_date.year, patching_date.month, 1).date()
    #  last_day =  calendar.monthrange(patching_date.year, patching_date.month)[1]
    #  patching_month_end = datetime(patching_date.year, patching_date.month, last_day).date()
    #  patching_month_start <= <= patching_month_end
     return datetime(patching_date.year, patching_date.month, 1).date() <= parsed_date 
    

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

def extract_links(current_offset=0):
    links = []
    html = fetch_security_notices(current_offset)
    
    soup = BeautifulSoup(html, features='lxml')
    articles = soup.select('article', class_='notice')  # Corrected the class name
    for article in articles:
        pub_date = article.find('p', class_="u-no-margin u-no-padding--top")
        if pub_date:
            parsed_date = parse_date2(pub_date.text.strip())
            if is_within_month(parsed_date, patching_date):
                print(url + article.find('a')['href'])
                links.append(url + article.find('a')['href'])
            else:
                return links    
   
    next_offset = current_offset + 10 

    return links + extract_links(next_offset) 
    
# def extract_links(current_offset=0, collected_links=None):
    if collected_links is None:
        collected_links = []

    try:
        html = fetch_security_notices(current_offset)
    except Exception as e:
        print(f"Error fetching security notices: {e}")
        return collected_links

    soup = BeautifulSoup(html, features='lxml')
    section = soup.find('section', class_='p-strip')
    articles = section.find_all('article', class_='notice')
    if not articles:
        print("No articles found with the given selector.")
        return collected_links

    new_links_found = False
    for article in articles:
        pub_date_elem = article.find('p', class_="u-no-margin u-no-padding--top")
        if pub_date_elem:
            try:
                parsed_date = parse_date2(pub_date_elem.text.strip())
            except Exception as e:
                print(f"Error parsing date: {e}")
                continue

            if is_within_month(parsed_date, patching_date):
                article_link_elem = article.find('a')
                if article_link_elem:
                    collected_links.append(url + article_link_elem['href'])
                    new_links_found = True
                else:
                    print("Article link not found.")
            else:
                # Continue processing other articles but stop recursion if an old article is found
                continue

    if new_links_found:
        next_offset = current_offset + 10
        return extract_links(next_offset, collected_links)
    else:
        return collected_links
def search_for_cves(text):
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
    # Find all matches of the pattern
    cves = cve_pattern.findall(text)
   
    # Remove duplicates by converting to a set and back to a list
    cves = list(set(cves))

    # Join the CVE identifiers into a single string
    cves_str = ', '.join(cves)
    print(cves_str)
    # Check if cves_str is empty and print the appropriate message
    if not cves_str:
        return 'N/A'
    else:
        return cves_str


async def extract_pages(links):
    big_data = []
    for link in links:
        if skip_link(link):
           log.warning('skiping this link : %s', link) 
           continue 
        # html = await _get_html(link)  
        # ["latin-1", "iso-8859-1", "windows-1251"]).unicode_markup ,from_encoding=html.encoding
        # soup = BeautifulSoup(html,features='lxml')
        # section = soup.find('section',class_="p-strip--suru-topped")
        max_retries = 10
        retry_count = 0
        while retry_count < max_retries:
            html = await _get_html(link)
            soup = BeautifulSoup(html, features='lxml')
            section = soup.find('section', class_="p-strip--suru-topped")
            time.sleep(2)
            if section:
                break  # Exit loop if section is found
            else:
                retry_count += 1
                log.warning(f"Retrying... (Attempt {retry_count}/{max_retries}")
                
        if not section:
            print(link)
        title = products = None
        if section:
            div_fixed = section.find('div', class_="u-fixed-width")
            rows = section.find_all('div', class_="row")
            if div_fixed and rows:
               title_element = div_fixed.find("h1")
               date_str = div_fixed.find('p',class_="p-muted-heading")
               if date_str:
                  issue_date = parse_date(date_str.text.strip()) 
            #    products = [li.text.strip()  for li in rows[0].find('ul',class_="p-inline-list").find_all("li",class_="p-inline-list__item") ]
               if title_element:
                    title = title_element.text.strip()
               col = rows[1].find('div',class_="col-8")
              
               if len(rows) > 2:
                    ref = rows[2].find('div', class_="col-8")
                    # Cves =  ', '.join([li.text.strip() for li in ref.find("ul")])
                    Cves = ', '.join([li.text.strip() for li in ref.find("ul") if li.text.strip().startswith('CVE-') and li.text.strip()])
                    # check if Cves string variable is empty if it's collect data from text not from ref..
                    if not Cves:
                      Cves =  search_for_cves(soup.get_text())
               else:
                   Cves =  'N/A'
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
                                    'Announcement links': f"https://ubuntu.com/security/notices/{title.split(':')[0]}"
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
     df["Release Date"] = pd.to_datetime(df["Release Date"],format="%d/%m/%Y").dt.date
     folder = 'collected'
     df_sorted = df.sort_values(by='OS')
     file_name = f'Ubuntu-Generated-Month-{patching_date.strftime("%B")}.xlsx'
     path = os.path.join(folder, file_name)
     if not os.path.exists(folder):
       os.makedirs(folder)
     df_sorted.to_excel(path, index=False) 
        
        

async def main():
    initialtime  = time.time()
    # extracrt & scraping data 
    links = extract_links()
    print(links)
    big_data = await extract_pages(links)
    save_data(big_data)
    log.info('successful finishing. Time taken: %.2f seconds' ,time.time() - initialtime)
    
if __name__ == "__main__":
   asyncio.run(main())
   
    
