from datetime import datetime, timezone, timedelta
import time
import requests
import logging
from tqdm import tqdm
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger("logger")

# API details
api_url = 'https://support.broadcom.com/group/ecx/solutionfiles/-/solutionFiles/getSolutionFiles'
order_url = "https://support.broadcom.com/web/ecx/solutiondetails/-/solutionDetails/createSolutionDownloadOrder"

# Cookies and headers (replace these with secure methods of authentication in production)
cookies = {
    'liferay-ingress-prd-us': '1733326101.061.40.143932|95b2e232c5e0be8e41c900a6b1ad87e6',
    'COOKIE_SUPPORT': 'true',
    'ac_client_user_id': 'c5048c2c-c03d-44bc-a6b2-6fd288cb8f91',
    'LFR_SESSION_STATE_20102': '1733326104493',
    'SAML_SP_SESSION_KEY': '_53942ce8422e9ead10eb6f5a0f2a621892fff4dd697fa064fa019ce5eaf5',
    'JSESSIONID': '1DA7451BFB4DF50208563E2D18C5A848',
    'OptanonAlertBoxClosed': '2024-12-04T15:30:37.317Z',
    'OptanonConsent': 'isGpcEnabled=0&datestamp=Wed+Dec+04+2024+16%3A53%3A57+GMT%2B0100+(GMT%2B01%3A00)&version=202410.1.0&browserGpcFlag=0&isIABGlobal=false&hosts=&consentId=5f6353f7-7480-4c82-95ae-0bd5aeef4851&interactionCount=1&isAnonUser=1&landingPath=NotLandingPage&groups=1%3A1%2C3%3A1%2C2%3A0%2C4%3A0&intType=3&geolocation=ES%3BMD&AwaitingReconsent=false',
    'LFR_SESSION_STATE_71940356': '1733327645204',
}
headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
}

# Payload configuration
current_date = "10/01/2024"
release = '8.0'
params = {
    'page': '0',
    'size': '50',
}
payload = {
    'displayGroup': 'VMware vSphere - Standard',
    'release': release,
    'os': '',
    'solutionOS': '',
    'component': '',
    'searchVal': '',
    'orderCol': 'CNFDATE',
    'orderSeq': 'DESC',
    'toDate': current_date,
}


def get_json(url, payload):
    """
    Sends a POST request and returns the JSON response.
    """
    try:
        log.info('Sending request to target URL')
        initial_time = time.time()
        response = requests.post(
            url,
            params=params,
            cookies=cookies,
            headers=headers,
            json=payload
        )

        if response.status_code == 200 or response.status_code == 201:
            log.info('Request successful. Status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - initial_time)
            return response.json()
        else:
            log.error('Unexpected status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - initial_time)
            return None
    except requests.exceptions.RequestException as error:
        log.error('Error during request: %s', error)
        return None


def filter_ordered_files(json_data, substring='-patch-FP.iso'):
    """
    Filters files matching the given substring in their file path.
    """
    filtered_files = [
        file_info for file_info in json_data.get('orderedFiles', [])
        if substring in file_info.get('filePath', '')
    ]
    return filtered_files


def get_download_links():
    """
    Fetches the download links for patches.
    """
    links = []
    patches = get_json(api_url, payload)
    if not patches or 'data' not in patches or 'solutions' not in patches['data']:
        log.error("No patches found or API response invalid.")
        return links

    for patch in patches['data']['solutions']:
        download_info = {
            'siteId': 105246,
            'downloadType': 'HTTP',
            'solutionList': [
                {
                    'patchId': patch["patchId"],
                    'os': '',
                    'solutionNumber': '',
                    'orderedFiles': filter_ordered_files(patch, substring='-patch-FP.iso')
                },
            ],
        }
        order_response = get_json(order_url, download_info)
        if order_response and 'data' in order_response and 'downloadUrl' in order_response['data']:
            links.append(order_response['data']['downloadUrl'])
    return links


def download_file_with_resume(url, output_path):
    """
    Downloads a file with a progress bar and support for resuming.
    """
    headers = {}
    if os.path.exists(output_path):
        file_size = os.path.getsize(output_path)
        headers['Range'] = f"bytes={file_size}-"
    else:
        file_size = 0

    with requests.get(url, stream=True, headers=headers) as response:
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0)) + file_size
        mode = 'ab' if file_size > 0 else 'wb'

        with open(output_path, mode) as file, tqdm(
            total=total_size, initial=file_size, unit='B', unit_scale=True, desc=os.path.basename(output_path)
        ) as progress_bar:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:  # Filter out keep-alive chunks
                    file.write(chunk)
                    progress_bar.update(len(chunk))

    log.info(f"Downloaded file to {output_path}")


def download_patches(download_dir="patches"):
    """
    Downloads all patches into the specified directory.
    """
    links = get_download_links()
    if not links:
        log.error("No download links found")
        return

    os.makedirs(download_dir, exist_ok=True)

    for idx, url in enumerate(links, 1):
        filename = f"patch_{idx}.iso"
        filepath = os.path.join(download_dir, filename)
        try:
            download_file_with_resume(url, filepath)
        except Exception as e:
            log.error(f"Failed to download {url}: {e}")


if __name__ == "__main__":
    download_patches()
