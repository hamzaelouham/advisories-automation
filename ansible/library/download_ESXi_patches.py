#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
from ansible.module_utils.basic import AnsibleModule
from pathlib import Path
from tqdm import tqdm
import requests
import logging
import time
import os



# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger("logger")

# API details
api_url = 'https://support.broadcom.com/group/ecx/solutionfiles/-/solutionFiles/getSolutionFiles'
order_url = "https://support.broadcom.com/web/ecx/solutiondetails/-/solutionDetails/createSolutionDownloadOrder"

# Cookies and headers (replace these with secure methods of authentication in production)

headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
}

# Payload configuration
def load_cookies(cookie_file):
    cookies = {}
    try:
        with open(cookie_file, 'r') as file:
            for line in file:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    cookies[key] = value
    except Exception as e:
        log.error(f"Failed to read cookies from file: {e}")
        raise
    return cookies


def run_module():
    
    module_args = {
        'date':{
            'type': 'str',
            'required': True
        },
        'release':{
            'type': 'str',
            'required': True
        },
        'path':{
            'type': 'str',
            'required': True
        },
        'cookie_file': { 
            'type': 'str',
            'required': True
        }
    }
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )
    cookie_file = module.params['cookie_file']
    if not os.path.exists(cookie_file):
        module.fail_json(msg=f"Cookie file not found: {cookie_file}")
    params = {
        'page': '0',
        'size': '50',
    }
    payload = {
        'displayGroup': 'VMware vSphere - Standard',
        'release': module.params['release'],
        'os': '',
        'solutionOS': '',
        'component': '',
        'searchVal': '',
        'orderCol': 'CNFDATE',
        'orderSeq': 'DESC',
        'toDate': module.params['date'],
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
                cookies=load_cookies(cookie_file),
                headers=headers,
                json=payload
            )

            if response.ok:  # Checks for 200 <= status_code < 400
                log.info('Request successful. Status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - initial_time)
                return response.json()
            else:
                log.error('Unexpected status code: %d. Time taken: %.2f seconds', response.status_code, time.time() - initial_time)
                return None
        except requests.exceptions.RequestException as error:
            log.error('Error during request: %s', error)
            return None

    def filter_ordered_files(json_data, substring='-depot.zip'):
        """
        Filters files matching the given substring in their file path.
        """
        return [
            file_info for file_info in json_data.get('orderedFiles', [])
            if substring in file_info.get('filePath', '')
        ]

    def get_download_links():
        """
        Fetches the download links for patches.
        """
        downloads = []
        patches = get_json(api_url, payload)
        if not patches or 'data' not in patches or 'solutions' not in patches['data']:
            module.fail_json(msg="No patches found or API response invalid.")  # Stop execution and return an error to Ansible
            return downloads  # This won't be executed, but it's here as a safeguard
           

        for patch in patches['data']['solutions']:
            ordered_files = filter_ordered_files(patch, substring='-depot.zip')
            if not ordered_files:
                log.warning(f"No matching files found for patch ID: {patch.get('patchId')}")
                continue

            download_info = {
                'siteId': 105246,
                'downloadType': 'HTTP',
                'solutionList': [
                    {
                        'patchId': patch["patchId"],
                        'os': '',
                        'solutionNumber': '',
                        'orderedFiles': ordered_files
                    },
                ],
            }
            order_response = get_json(order_url, download_info)
            if order_response and 'data' in order_response and 'downloadUrl' in order_response['data']:
                downloads.append({
                    'link': order_response['data']['downloadUrl'],
                    'filename': Path(ordered_files[0]["filePath"]).name
                })
        return downloads

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

        for idx, link in enumerate(links, 1):
            filename = link['filename']
            filepath = os.path.join(download_dir, filename)
            try:
                log.info(f"Downloading {filename} ({idx}/{len(links)})")
                download_file_with_resume(link['link'], filepath)
            except Exception as e:
                log.error(f"Failed to download {filename}: {e}")

    result = {
        'changed' : False,
        'failed': True,
        'message' : 'failed to download patches...!'
    }



    try:
        download_patches(download_dir= module.params['path'])
        result['message'] = "patches downloaded Successfully"  
        result["failed"] = False
        result['changed'] = True
        module.exit_json(**result)
    except KeyError:
        module.exit_json(**result)

    

def main():
    run_module()


if __name__ == '__main__':
    main()