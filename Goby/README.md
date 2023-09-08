# Goby的POC

**2023年6月28日更新，共228个POC**

**因为Goby的原因，其中部分POC可能没法用，比如禅道的bypass rce，原因就是goby无法写出client=\`id\`的POC**

**还有Apache HTTP Server 2.4.49 路径穿越漏洞 CVE-2021-41773和Openfire Administration Console 权限绕过漏洞 CVE-2023-32315漏洞的POC无法使用，原因就是URL存在特殊字符。**

**一样的因为url不能带有url编码过的特殊字符。因此Contec SolarView Compact 安全漏洞 CVE-2023-23333漏洞的poc也没法用。**

---

**本项目停更！！用afrog和nuclei多好，非要用goby，poc又少又烦，吃相难看，建议kscan或者其他工具（goby也行扫扫端口还是可以的）扫描提出web资产然后afrog和nuclei扫nday**

**脚本小子就要有脚本小子的觉悟（afrog、nuclei真香）。**
