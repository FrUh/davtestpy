#!/usr/bin/python
import requests
from optparse import OptionParser
from urlparse import urlparse
import os
import sys
import urllib3
import re


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def upload_file(remote, local, auth, request_settings):
    print("[*] Uploading file: {}".format(remote))

    with open(local, "rb") as f:
        data = f.read(65536)
        response = requests.put(remote, auth=auth, proxies=request_settings, verify=False, data=data)
    return response, data


def check_vuln(response, uploaded_data):
    exec_match = re.search(r"execmatch=(.*)\n", uploaded_data)
    
    if exec_match is None:
        raise Exception("Check your test payload. It must contain execmatch=STR\\n")

    # m = re.search("content=[^=].*(49[\.,]?92|YEAR\:[0-9]{4}\:YEAR)", response.text)
    m = re.search("content=" + exec_match.group(1).strip(), response.text)

    if m is not None:
        print("[+] VULNERABLE")
    else:
        print("[-] Not vulnerable, status code: {}".format(response.status_code))


def check_content_type(content_type):
    xss_types = ["html", "text/xml"]

    for t in xss_types:
        if t in content_type:
            return True

    return False


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-u", "--url", dest="url", action="store", help="hostname")
    parser.add_option("-l", "--username", dest="username", action="store", help="username")
    parser.add_option("-p", "--password", dest="password", action="store", help="password")
    parser.add_option("--proxy", dest="proxy", action="store", help="proxy URL")
    parser.add_option("--clean", dest="clean", action="store_true", default=False, help="remove uploaded files")
    parser.add_option("--dont-test", dest="test", action="store_false", default=True, help="do not upload test files")
    parser.add_option("--upload-file", dest="upload_file", action="store", default=None, help="upload just specified file")

    (options, args) = parser.parse_args()

    request_settings = {
        "http": options.proxy,
        "https": options.proxy
    }
    if options.url is None:
        parser.error("Missing url")

    if options.url[-1] == "/":
        options.url = options.url[:-1]
    url = urlparse(options.url)

    if options.username is not None and options.password is not None:
        auth = (options.username, options.password)
    else:
        auth = None

    if options.upload_file is not None:
        # upload
        upload_file("{}/justtobelonger_{}".format(options.url, os.path.basename(options.upload_file)), options.upload_file, auth, request_settings)

    else:
        # get all test files
        no_test_files = True
        test_folder = sys.path[0] + os.sep + "tests"
        for root, dirs, files in os.walk(test_folder, topdown=False):
            for name in files:
                no_test_files = False
                webdav_name = "justtobelonger_{}".format(name)
                remote_url = "{}/{}".format(options.url, webdav_name)

                if options.test:
                    # upload
                    _, uploaded_data = upload_file(remote_url, os.path.join(root, name), auth, request_settings)

                    # check vuln
                    response = requests.get(remote_url, auth=auth, proxies=request_settings, verify=False)
                    
                    check_vuln(response, uploaded_data)
                if options.clean:
                    print("[*] Removing file: {}".remote_url)
                    response = requests.delete(remote_url, auth=auth, proxies=request_settings, verify=False)
        if no_test_files:
            print("[!] ERROR: not test files in test folder '{}'".format(test_folder))
