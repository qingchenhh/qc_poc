# Goby的POC

**2023年6月28日更新，共228个POC**

**因为Goby的原因，其中部分POC可能没法用，比如禅道的bypass rce，原因就是goby无法写出client=\`id\`的POC**

**还有Apache HTTP Server 2.4.49 路径穿越漏洞 CVE-2021-41773和Openfire Administration Console 权限绕过漏洞 CVE-2023-32315漏洞的POC无法使用，原因就是URL存在特殊字符。**

**一样的因为url不能带有url编码过的特殊字符。因此Contec SolarView Compact 安全漏洞 CVE-2023-23333漏洞的poc也没法用。**

还是用人家xray就好，人家内置那么多的poc，反正基本不用自己写，脚本小子就要有脚本小子的觉悟。
