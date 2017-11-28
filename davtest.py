#!/usr/bin/python
import requests
from optparse import OptionParser
from urlparse import urlparse
import os
import urllib3
import re


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def upload_file(remote, local, auth, request_settings):
    print("[*] Uploading file: {}".format(remote))

    with open(local, "rb") as f:
        data = f.read(65536)
        response = requests.put(remote, auth=auth, proxies=request_settings, verify=False, data=data)
    return response


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
        for root, dirs, files in os.walk("tests", topdown=False):
            for name in files:
                webdav_name = "justtobelonger_{}".format(name)

                if options.test:
                    # upload
                    upload_file("{}/{}".format(options.url, webdav_name), os.path.join(root, name), auth, request_settings)

                    # check vuln
                    response = requests.get("{}/{}".format(options.url, webdav_name), auth=auth, proxies=request_settings, verify=False)
                    m = re.search("content=[^=].*(49[\.,]?92|YEAR\:[0-9]{4}\:YEAR)", response.text)

                    if m is not None:
                        print("[+] VULNERABLE")
                    else:
                        print("[-] not vulnerable")

                if options.clean:
                    print("[*] Removing file: {}/{}".format(options.url, webdav_name))
                    response = requests.delete("{}/{}".format(options.url, webdav_name), auth=auth, proxies=request_settings, verify=False)
