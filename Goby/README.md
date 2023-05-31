# Goby的POC

**2023年5月31日更新，共213个POC**

**因为Goby的原因，其中部分POC可能没法用，比如禅道的bypass rce，原因就是goby无法写出client=\`id\`的POC**

**还有Apache HTTP Server 2.4.49 路径穿越漏洞 CVE-2021-41773和Openfire Administration Console 权限绕过漏洞 CVE-2023-32315漏洞的POC无法使用，原因就是URL存在特殊字符。**

以下是写Goby发现的一些问题：

我发现goby的指纹归类有点乱。

我自己写了一个扫tomcat弱口令的poc，当然就试一下admin/admin，tomcat/tomcat这种，虽然goby带有爆破，但是平时怕跑ssh和其他服务弱口令锁了系统，就感觉还是写一个这种很简单的，说不定某次扫描能给自己带来一个惊喜。

我规则是这样写的app="APACHE-Tomcat" && "/manager/html"，试了一下能搜到很多数据的，就这个了。

![1680572639679](images/1680572639679.png)

 再然后我打开了一个vulfocus的靶场来测试一下，结果没扫到。 

![1680572659466](images/1680572659466.png)

 我觉得不应该啊，这东西我都看到指纹识别出tomcat了，图标都出现了，我就点了一下这个指纹，发现指纹是product="Apache-Tomcat"。 

![1680572678238](images/1680572678238.png)

？？？？你tm到底是个啥？app？还是server？还是product？

无奈之下我改成了这个app="APACHE-Tomcat" || product="Apache-Tomcat"，然后就扫到了。

![1680572692732](images/1680572692732.png)

更牛逼的是，我后面发现，万物皆可product

哎，我管你是什么框架也好

![1680572759517](images/1680572759517.png)

应用也好。

![1680572794873](images/1680572794873.png)

![1680572816100](images/1680572816100.png)

![1680573597804](images/1680573597804.png)

还是上面说的tomcat中间件也好，我全product。

还是用人家xray就好，人家内置那么多的poc，反正基本不用自己写，脚本小子就要有脚本小子的觉悟。

最后建议，写goby的poc用的规则还是用我上面那个例子Jeecg-Boot一样的，去找找body中的特性，然后写body="Jeecg-Boot"，别用官方的什么app或者什么乱七八糟的，妈呀，乱，指纹识别不到。而且指纹尽量放宽，反正我是觉得**宁愿多扫，出现误报，也不愿意漏扫**。

我是个垃圾！没办法！
