import hashlib
import json
import os
import sys
import time
from pathlib import Path
from pprint import pprint

from virustotal import Virustotal

API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', None)
INSTALLER_FILE_SUFFIX = os.environ.get("INSTALLER_FILE_SUFFIX", "x86.exe")
WORKSPACE_DIR = os.environ.get('WORKSPACE_DIR', '.')

WAIT_TIME = 2 * 60  # 2 MINUTES
MAX_WAIT_COUNT = 5  # Wait 5 times -> 10 minutes max


def find_file(base_path, file_suffix_with_extension):
    return list(base_path.glob('*' + file_suffix_with_extension))


def get_file_hash(filename):
    BLOCK_SIZE = 65536

    file_hash = hashlib.sha256()
    with open(filename, 'rb') as f:
        fb = f.read(BLOCK_SIZE)
        while len(fb) > 0:
            file_hash.update(fb)
            fb = f.read(BLOCK_SIZE)
    result = file_hash.hexdigest()
    return result


def get_upload_url(vt_api):
    upload_url_response = vt_api.request("files/upload_url", method="GET")
    upload_url = upload_url_response.data
    return upload_url


def upload_file(vt_api, upload_url, filename):
    # Create dictionary containing the file to send for multipart encoding upload
    files = {"file": (os.path.basename(filename), open(os.path.abspath(filename), "rb"))}

    uploaded_response = vt_api.request(upload_url, files=files, method="POST")
    upload_id = uploaded_response.json()['data']['id']
    return upload_id


def get_file_analysis(vt_api, upload_id):
    analysis_response = vt_api.request(f"analyses/{upload_id}")
    pprint(analysis_response.data)
    analysis_response_json = analysis_response.json()['data']
    return analysis_response_json


def is_file_safe(analysis_json):
    stats = analysis_json['attributes']['stats']
    if stats['malicious'] == 0 and stats['suspicious'] == 0:
        return True
    return False


def write_analysis_result_to_file(analysis_json, filename, file_hash):
    analysis_filename = filename + ".analysis.json"
    print(f"Analysis results file: {analysis_filename}")

    with open(analysis_filename, 'w') as file:
        analysis_json['filename'] = filename
        analysis_json['filehash'] = file_hash
        file.write(json.dumps(analysis_json, indent=1))


def run_analysis(filename):
    vt_api = Virustotal(API_KEY=API_KEY, API_VERSION="v3")

    # Since the size of the file will be higher than 32MB, an upload url is required.
    upload_url = get_upload_url(vt_api)
    upload_id = upload_file(vt_api, upload_url, filename)
    print(f"File upload id: {upload_id}")

    file_hash = get_file_hash(filename)
    print(f"VirusTotal Results URL: https://www.virustotal.com/gui/file/{file_hash}/detection")

    # It takes time to complete the analysis, poll if analysis is complete.
    num_waits = MAX_WAIT_COUNT

    while num_waits > 0:
        analysis_json = get_file_analysis(vt_api, upload_id)
        analysis_status = analysis_json['attributes']['status']

        if analysis_status == 'completed':
            # write the analysis result to a file for reference
            write_analysis_result_to_file(analysis_json, filename, file_hash)

            # check if the file is safe based on the results
            if is_file_safe(analysis_json):
                print("Installer file is good to publish")
                sys.exit(0)
            else:
                print("Malicious file!")
                sys.exit(-1)

        # If the analysis is not complete yet, wait
        time.sleep(WAIT_TIME)
        num_waits -= 1

    # If still not finished, then simply fail the job
    print("\nDid not receive the reports yet. Failing the job")
    print(f"VirusTotal Results URL: https://www.virustotal.com/gui/file/{file_hash}/detection")
    sys.exit(-1)


if __name__ == '__main__':
    base_path = Path(WORKSPACE_DIR).resolve().absolute()
    print(f"Workspace directory: {base_path}")
    print(f"Installer file suffix: {INSTALLER_FILE_SUFFIX}")

    installer_files = find_file(base_path, INSTALLER_FILE_SUFFIX)
    if not installer_files:
        print(f"No installer files found. Exiting...")
        sys.exit(1)

    for installer_file in installer_files:
        installer_file_fullpath = str(installer_file.absolute())
        print("Checking file:", installer_file_fullpath)
        run_analysis(installer_file_fullpath)
